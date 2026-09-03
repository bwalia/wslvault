//! Outbound email — invitation delivery over SMTP.
//!
//! # Configuration
//!
//! All from the environment, all required together:
//!
//! | Variable         | Example                        |
//! |------------------|--------------------------------|
//! | `SMTP_HOST`      | `smtp.gmail.com`               |
//! | `SMTP_PORT`      | `587` (STARTTLS) or `465`      |
//! | `SMTP_USERNAME`  | `you@example.com`              |
//! | `SMTP_PASSWORD`  | a Gmail **app password**       |
//! | `SMTP_FROM`      | `WSLVault <you@example.com>`   |
//! | `VAULT_PUBLIC_URL` | `https://vault.example.com`  |
//!
//! Gmail rejects an account password here; it needs an app password issued
//! against an account with 2-Step Verification on.
//!
//! # Why an unconfigured mailer is not an error
//!
//! [`Mailer::from_env`] returns `None` when SMTP is not set up, and invitation
//! creation still succeeds — the caller gets the invitation URL back and can
//! deliver it themselves. Refusing to create invitations without SMTP would
//! make the whole onboarding path unusable in local development and in any
//! deployment whose operator hands links over in a chat window. What must not
//! happen is a *silent* failure: a caller that believes an email went out when
//! it did not, so [`Mailer::send_invitation`] returns `Result` and the handler
//! reports delivery separately from creation.

use lettre::message::{header::ContentType, Mailbox, MultiPart, SinglePart};
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};
use tracing::{info, warn};

/// A configured SMTP sender.
#[derive(Clone)]
pub struct Mailer {
    transport: AsyncSmtpTransport<Tokio1Executor>,
    from: Mailbox,
}

impl std::fmt::Debug for Mailer {
    /// Hand-written so the transport's credentials cannot reach a log through a
    /// derived `Debug` on some struct that happens to contain a `Mailer`.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Mailer")
            .field("from", &self.from.to_string())
            .finish_non_exhaustive()
    }
}

impl Mailer {
    /// Build from the environment, or `None` when SMTP is not configured.
    ///
    /// Logs which variable is missing. An operator who expected mail to work
    /// should be able to tell why it did not from the startup log alone.
    pub fn from_env() -> Option<Self> {
        let host = non_empty("SMTP_HOST")?;
        let from_raw = non_empty("SMTP_FROM").unwrap_or_else(|| {
            warn!("SMTP_FROM is not set — falling back to SMTP_USERNAME as the sender");
            String::new()
        });

        let username = non_empty("SMTP_USERNAME");
        let password = non_empty("SMTP_PASSWORD");

        let from_str = if from_raw.is_empty() {
            username.clone()?
        } else {
            from_raw
        };

        let from: Mailbox = match from_str.parse() {
            Ok(m) => m,
            Err(e) => {
                warn!(error = %e, "SMTP_FROM is not a valid address — email disabled");
                return None;
            }
        };

        let port: u16 = std::env::var("SMTP_PORT")
            .ok()
            .and_then(|p| p.parse().ok())
            .unwrap_or(587);

        // 465 is implicit TLS; 587 and everything else negotiate STARTTLS.
        // Getting this backwards fails at connect time rather than sending in
        // the clear, but the message is obscure, so it is decided here.
        let builder = if port == 465 {
            AsyncSmtpTransport::<Tokio1Executor>::relay(&host)
        } else {
            AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&host)
        };

        let builder = match builder {
            Ok(b) => b.port(port),
            Err(e) => {
                warn!(error = %e, host = %host, "SMTP relay could not be constructed — email disabled");
                return None;
            }
        };

        let transport = match (username, password) {
            (Some(u), Some(p)) => builder.credentials(Credentials::new(u, p)).build(),
            _ => {
                // Unauthenticated SMTP is normal for an internal relay, so this
                // is a warning rather than a refusal.
                warn!("SMTP_USERNAME/SMTP_PASSWORD not both set — connecting without authentication");
                builder.build()
            }
        };

        info!(host = %host, port, from = %from, "SMTP configured; invitation emails will be sent");
        Some(Self { transport, from })
    }

    /// Send an invitation. Returns `Err` with a description on failure.
    pub async fn send_invitation(
        &self,
        to: &str,
        tenant_name: &str,
        url: &str,
        expires_in_hours: i64,
    ) -> Result<(), String> {
        let to_box: Mailbox = to
            .trim()
            .parse()
            .map_err(|e| format!("'{to}' is not a valid email address: {e}"))?;

        let subject = format!("You have been invited to {tenant_name} on WSLVault");

        let message = Message::builder()
            .from(self.from.clone())
            .to(to_box)
            .subject(subject)
            // Both parts, because a plain-text-only client would otherwise show
            // the recipient nothing but a bare URL with no explanation of what
            // it is or that it expires.
            .multipart(
                MultiPart::alternative()
                    .singlepart(
                        SinglePart::builder()
                            .header(ContentType::TEXT_PLAIN)
                            .body(plain_body(tenant_name, url, expires_in_hours)),
                    )
                    .singlepart(
                        SinglePart::builder()
                            .header(ContentType::TEXT_HTML)
                            .body(html_body(tenant_name, url, expires_in_hours)),
                    ),
            )
            .map_err(|e| format!("could not build the invitation email: {e}"))?;

        self.transport
            .send(message)
            .await
            .map_err(|e| format!("SMTP delivery failed: {e}"))?;

        Ok(())
    }
}

fn non_empty(var: &str) -> Option<String> {
    match std::env::var(var) {
        Ok(v) if !v.trim().is_empty() => Some(v.trim().to_string()),
        _ => {
            warn!("{var} is not set");
            None
        }
    }
}

fn plain_body(tenant_name: &str, url: &str, hours: i64) -> String {
    format!(
        "You have been invited to set up access to {tenant_name} on WSLVault.\n\n\
         Open this link to get started:\n\n{url}\n\n\
         The link works once, and expires in {hours} hours. If it expires, ask \
         whoever invited you for a new one.\n\n\
         You will be asked to set up an authenticator app on your phone. Have it \
         to hand — the whole thing takes about five minutes.\n\n\
         If you were not expecting this invitation, you can ignore this email. \
         Nothing happens until the link is opened.\n"
    )
}

/// Deliberately plain HTML: inline styles only, a table-free layout, no images
/// and no web fonts. Email clients silently drop stylesheets and remote assets,
/// and a link the recipient cannot see is an invitation that goes unanswered.
fn html_body(tenant_name: &str, url: &str, hours: i64) -> String {
    let tenant = escape_html(tenant_name);
    let href = escape_html(url);
    format!(
        r#"<div style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;max-width:520px;margin:0 auto;padding:24px;color:#1a1a1a;line-height:1.6">
  <h1 style="font-size:20px;margin:0 0 16px">You have been invited to {tenant}</h1>
  <p style="margin:0 0 16px">Someone has invited you to set up access to <strong>{tenant}</strong> on WSLVault.</p>
  <p style="margin:0 0 24px">
    <a href="{href}" style="display:inline-block;background:#2b7a6f;color:#ffffff;text-decoration:none;padding:12px 20px;border-radius:8px;font-weight:600">Set up my access</a>
  </p>
  <p style="margin:0 0 16px;font-size:14px;color:#555">
    This link works <strong>once</strong> and expires in <strong>{hours} hours</strong>.
    If it expires, ask whoever invited you for a new one.
  </p>
  <p style="margin:0 0 16px;font-size:14px;color:#555">
    You will be asked to set up an authenticator app on your phone, so have it to hand. The whole thing takes about five minutes.
  </p>
  <p style="margin:24px 0 0;font-size:13px;color:#777">
    If the button does not work, copy this address into your browser:<br>
    <span style="word-break:break-all">{href}</span>
  </p>
  <p style="margin:16px 0 0;font-size:13px;color:#777">
    If you were not expecting this, you can ignore this email. Nothing happens until the link is opened.
  </p>
</div>"#
    )
}

/// Escape for HTML text and attribute contexts.
///
/// The tenant name is operator-supplied and the URL is built from
/// `VAULT_PUBLIC_URL`; neither is trusted enough to interpolate raw into
/// markup that lands in someone's inbox.
fn escape_html(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_markup_in_the_tenant_name() {
        let body = html_body("<script>alert(1)</script>", "https://v.test/i/x", 72);
        assert!(!body.contains("<script>"));
        assert!(body.contains("&lt;script&gt;"));
    }

    #[test]
    fn escapes_quotes_so_the_href_cannot_be_broken_out_of() {
        let body = html_body("Acme", "https://v.test/i/\" onmouseover=\"evil()", 72);
        assert!(!body.contains("onmouseover=\"evil()"));
        assert!(body.contains("&quot;"));
    }

    #[test]
    fn both_bodies_carry_the_url_and_expiry() {
        let url = "https://vault.example.com/invite/tok123";
        for body in [plain_body("Acme", url, 48), html_body("Acme", url, 48)] {
            assert!(body.contains(url), "the recipient must be able to reach the link");
            assert!(body.contains("48"), "the expiry window must be stated");
        }
    }

    /// The plain-text part must stand alone — many clients render only it.
    #[test]
    fn plain_body_explains_itself_without_the_html_part() {
        let body = plain_body("Acme", "https://v.test/i/x", 72);
        assert!(body.contains("once"), "single-use must be stated");
        assert!(body.contains("authenticator app"));
    }
}

use utoipa::OpenApi;

#[derive(OpenApi)]
#[openapi(
    paths(
        crate::auth::register,
        crate::auth::current_consent_documents,
        crate::auth::login,
        crate::auth::refresh,
        crate::auth::verify_email,
        crate::auth::request_password_reset,
        crate::auth::reset_password,
        crate::auth::me,
        crate::auth::update_me,
        crate::auth::delete_me,
        crate::auth::export_me,
        crate::auth::logout,
        crate::applications::claim_guest_applications,
        crate::applications::create_authenticated,
        crate::applications::create_guest,
        crate::applications::continue_authenticated,
        crate::applications::continue_guest,
        crate::applications::list_mine,
        crate::applications::get_one,
        crate::opportunities::list_public,
        crate::opportunities::get_public,
        crate::opportunities::list_admin,
        crate::opportunities::create,
        crate::opportunities::update,
        crate::proofs::upload,
        crate::proofs::queue,
        crate::proofs::download,
        crate::proofs::decide,
        crate::events::create_program,
        crate::events::create_event,
        crate::events::link_opportunity,
        crate::events::check_in,
        crate::events::paper_check_in,
        crate::auth::publish_consent_documents,
        crate::auth::assign_role,
        crate::auth::remove_role,
        crate::auth::admin_anonymise_user,
        crate::auth::list_audit_logs,
        crate::reports::funnel,
        crate::reports::applications_csv,
        crate::health_live,
        crate::health_ready
    ),
    components(schemas(
        crate::auth::RegisterRequest,
        crate::auth::LoginRequest,
        crate::auth::RefreshRequest,
        crate::auth::VerifyEmailRequest,
        crate::auth::PasswordResetRequest,
        crate::auth::ResetPasswordRequest,
        crate::auth::AssignRoleRequest,
        crate::auth::PublishConsentDocumentsRequest,
        crate::auth::ProfileUpdate,
        crate::auth::DeleteAccountRequest,
        crate::auth::AdminAnonymiseRequest,
        crate::applications::CreateApplication,
        crate::applications::CreateGuestApplication,
        crate::applications::GuestContinueRequest,
        crate::opportunities::CreateOpportunity,
        crate::opportunities::UpdateOpportunity,
        crate::proofs::VerificationDecision,
        crate::proofs::UploadProofRequest,
        crate::events::CreateProgram,
        crate::events::CreateEvent,
        crate::events::CheckInRequest,
        crate::events::PaperCheckInRequest
    )),
    tags(
        (name = "Authentication", description = "Account registration, login, sessions, and profile"),
        (name = "Consent", description = "Published privacy and terms documents"),
        (name = "Applications", description = "Student and guest applications"),
        (name = "Opportunities", description = "Public listings and staff opportunity management"),
        (name = "Proofs", description = "Private proof uploads and verification"),
        (name = "Programs and events", description = "Program, event, and check-in management"),
        (name = "Administration", description = "Administrative user, role, and audit operations"),
        (name = "Reports", description = "Opportunity reports and CSV exports"),
        (name = "Health", description = "Service liveness and dependency readiness")
    ),
    modifiers(&BearerAuth),
    info(
        title = "Scried Backend API",
        version = "0.1.0",
        description = "Interactive API reference for the Scried backend. Protected operations use a bearer access token."
    )
)]
pub struct ApiDoc;

struct BearerAuth;

impl utoipa::Modify for BearerAuth {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        openapi
            .components
            .get_or_insert_with(Default::default)
            .add_security_scheme(
                "bearerAuth",
                utoipa::openapi::security::SecurityScheme::Http(
                    utoipa::openapi::security::Http::new(
                        utoipa::openapi::security::HttpAuthScheme::Bearer,
                    ),
                ),
            );
    }
}

#[cfg(test)]
mod tests {
    use super::ApiDoc;
    use utoipa::OpenApi;

    #[test]
    fn openapi_document_includes_auth_schemas_and_protected_operations() {
        let document =
            serde_json::to_value(ApiDoc::openapi()).expect("OpenAPI document serializes");
        let paths = document["paths"].as_object().expect("OpenAPI paths exist");

        assert!(paths.contains_key("/api/v1/auth/register"));
        assert!(paths.contains_key("/api/v1/applications/{application_id}/proofs"));
        assert!(paths.contains_key("/api/v1/health/ready"));
        assert_eq!(
            document["paths"]["/api/v1/auth/me"]["get"]["security"][0]["bearerAuth"],
            serde_json::json!([])
        );
        assert!(document["components"]["schemas"]["RegisterRequest"].is_object());
        assert!(document["components"]["securitySchemes"]["bearerAuth"].is_object());
    }
}

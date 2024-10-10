import {
    AdminSetUserMFAPreferenceRequest,
    AdminSetUserMFAPreferenceResponse,
  } from "aws-sdk/clients/cognitoidentityserviceprovider";
  import { InvalidParameterError } from "../errors";
  import { Target } from "./Target";
  import { Context } from "../services/context";
  import { Services } from "../services";
  
  export type AdminSetUserMFAPreferenceTarget = Target<
    AdminSetUserMFAPreferenceRequest,
    AdminSetUserMFAPreferenceResponse
  >;
  
  type AdminSetUserMFAPreferenceServices = Pick<
    Services,
    "cognito" | "triggers" | "config"
  >;
  
  export const AdminSetUserMFAPreference =
    ({ cognito, triggers, config }: AdminSetUserMFAPreferenceServices): AdminSetUserMFAPreferenceTarget =>
    async (ctx, req) => {
      // Fetch the user pool for the given user
      const userPool = await cognito.getUserPool(ctx, req.UserPoolId);
      const user = await userPool.getUserByUsername(ctx, req.Username);
  
      if (!user) {
        throw new InvalidParameterError("User does not exist");
      }
  
      // Prepare MFA settings
      const smsMfaSettings = req.SMSMfaSettings
        ? {
            Enabled: req.SMSMfaSettings.Enabled,
            PreferredMfa: req.SMSMfaSettings.PreferredMfa,
          }
        : undefined;
  
      const softwareTokenMfaSettings = req.SoftwareTokenMfaSettings
        ? {
            Enabled: req.SoftwareTokenMfaSettings.Enabled,
            PreferredMfa: req.SoftwareTokenMfaSettings.PreferredMfa,
          }
        : undefined;
  
      // Update user MFA preferences
      await userPool.setUserMFAPreference(ctx, user, {
        SMSMfaSettings: smsMfaSettings,
        SoftwareTokenMfaSettings: softwareTokenMfaSettings,
      });

  
      // Invoke PostAuthentication if applicable
      if (triggers.enabled("PostAuthentication")) {
        await triggers.postAuthentication(ctx, {
          clientId: req.ClientId,
          clientMetadata: req.ClientMetadata,
          source: "PostAuthentication_Authentication",
          username: user.Username,
          userPoolId: userPool.options.Id,
          userAttributes: user.Attributes,
        });
      }
  
      return {};
    };
  
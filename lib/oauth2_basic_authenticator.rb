# frozen_string_literal: true

class OAuth2BasicAuthenticator < Auth::ManagedAuthenticator
  def name
    "oauth2_basic"
  end

  def can_revoke?
    SiteSetting.oauth2_allow_association_change
  end

  def can_connect_existing_user?
    SiteSetting.oauth2_allow_association_change
  end

  def register_middleware(omniauth)
    omniauth.provider :oauth2_basic,
                      name: name,
                      setup:
                        lambda { |env|
                          opts = env["omniauth.strategy"].options
                          opts[:client_id] = SiteSetting.oauth2_client_id
                          opts[:client_secret] = SiteSetting.oauth2_client_secret
                          opts[:provider_ignores_state] = SiteSetting.oauth2_disable_csrf
                          opts[:client_options] = {
                            authorize_url: SiteSetting.oauth2_authorize_url,
                            token_url: SiteSetting.oauth2_token_url,
                            token_method: SiteSetting.oauth2_token_url_method.downcase.to_sym,
                          }
                          opts[:authorize_options] =
                            SiteSetting.oauth2_authorize_options.split("|").map(&:to_sym)

                          if SiteSetting.oauth2_authorize_signup_url.present? &&
                              ActionDispatch::Request.new(env).params["signup"].present?
                            opts[:client_options][:authorize_url] = SiteSetting.oauth2_authorize_signup_url
                          end

                          if SiteSetting.oauth2_send_auth_header? && SiteSetting.oauth2_send_auth_body?
                            opts[:client_options][:auth_scheme] = :request_body
                            opts[:token_params] = {
                              headers: {
                                "Authorization" => basic_auth_header,
                              },
                            }
                          elsif SiteSetting.oauth2_send_auth_header?
                            opts[:client_options][:auth_scheme] = :basic_auth
                          else
                            opts[:client_options][:auth_scheme] = :request_body
                          end

                          opts[:scope] = SiteSetting.oauth2_scope if SiteSetting.oauth2_scope.present?

                          opts[:client_options][:connection_build] = lambda do |builder|
                            if SiteSetting.oauth2_debug_auth && defined?(OAuth2FaradayFormatter)
                              builder.response :logger,
                                               Rails.logger,
                                               { bodies: true, formatter: OAuth2FaradayFormatter }
                            end

                            builder.request :url_encoded
                            builder.adapter FinalDestination::FaradayAdapter
                          end
                        }
  end

  def basic_auth_header
    "Basic " + Base64.strict_encode64("#{SiteSetting.oauth2_client_id}:#{SiteSetting.oauth2_client_secret}")
  end

  def log(info)
    Rails.logger.warn("OAuth2 Debugging: #{info}") if SiteSetting.oauth2_debug_auth
  end

  def fetch_user_details(token, id)
    user_json_url = SiteSetting.oauth2_user_json_url.sub(":token", token.to_s).sub(":id", id.to_s)
    user_json_method = SiteSetting.oauth2_user_json_url_method.downcase.to_sym

    bearer_token = "Bearer #{token}"
    connection = Faraday.new { |f| f.adapter FinalDestination::FaradayAdapter }
    headers = { "Authorization" => bearer_token, "Accept" => "application/json" }

    begin
      user_json_response = connection.run_request(user_json_method, user_json_url, nil, headers)

      log <<-LOG
        user_json request: #{user_json_method} #{user_json_url}
        request headers: #{headers}
        response status: #{user_json_response.status}
        response body:
        #{user_json_response.body}
      LOG

      if user_json_response.status == 200
        user_json = JSON.parse(user_json_response.body)
        log("user_json:\n#{user_json.to_yaml}")
        result = {}

        if user_json.present?
          %w[user_id username name email email_verified avatar].each do |prop|
            json_walk(result, user_json, prop.to_sym)
          end
        end
        result
      else
        Rails.logger.error "OAuth2 User Fetch Error: Unexpected response code #{user_json_response.status}"
        nil
      end
    rescue JSON::ParserError => e
      Rails.logger.error "OAuth2 JSON Parsing Error: #{e.class} - #{e.message}"
      nil
    rescue Faraday::ConnectionFailed => e
      Rails.logger.error "OAuth2 Connection Error: #{e.class} - #{e.message}"
      nil
    rescue StandardError => e
      Rails.logger.error "OAuth2 Unknown Error: #{e.class} - #{e.message}"
      nil
    end
  end

  def after_authenticate(auth, existing_account: nil)
    log "after_authenticate response: #{auth.to_yaml}"

    begin
      if SiteSetting.oauth2_fetch_user_details? && SiteSetting.oauth2_user_json_url.present?
        fetched_user_details = fetch_user_details(auth["credentials"]["token"], auth["uid"])

        if fetched_user_details
          %w[user_id username name email email_verified avatar].each do |prop|
            auth["info"][prop] = fetched_user_details[prop.to_sym] if fetched_user_details[prop.to_sym]
          end
        else
          Rails.logger.error "OAuth2 Authentication Error: Could not fetch user details."
          return fail!(
            :invalid_response,
            OmniAuth::Error.new("Failed to fetch user details from OAuth2 provider.")
          )
        end
      end

      # ✅ PKCE: Ensure `code_verifier` is deleted after authentication
      if auth["rack.session"] && auth["rack.session"]["oauth2_code_verifier"]
        Rails.logger.info "OAuth2 PKCE: Clearing stored code_verifier from session."
        auth["rack.session"].delete("oauth2_code_verifier")
      end

      super(auth, existing_account: existing_account)
    rescue StandardError => e
      Rails.logger.error "OAuth2 Authentication Error: #{e.class} - #{e.message}"

      return fail!(
        :unknown_error,
        OmniAuth::Error.new("An unknown error occurred during authentication.")
      )
    end
  end

  def enabled?
    SiteSetting.oauth2_enabled
  end
end

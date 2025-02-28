# frozen_string_literal: true

require 'securerandom'
require 'base64'
require 'openssl'
require 'faraday'
require 'json'

class OmniAuth::Strategies::Oauth2Basic < ::OmniAuth::Strategies::OAuth2
  option :name, "oauth2_basic"

  uid do
    if path = SiteSetting.oauth2_callback_user_id_path.split(".")
      recurse(access_token, [*path]) if path.present?
    end
  end

  info do
    if paths = SiteSetting.oauth2_callback_user_info_paths.split("|")
      result = {}
      paths.each do |p|
        segments = p.split(":")
        if segments.length == 2
          key = segments.first
          path = [*segments.last.split(".")]
          result[key] = recurse(access_token, path)
        end
      end
      result
    end
  end

  def callback_url
    Discourse.base_url_no_prefix + script_name + callback_path
  end

  def recurse(obj, keys)
    return nil unless obj
    k = keys.shift
    result = obj.respond_to?(k) ? obj.send(k) : obj[k]
    keys.empty? ? result : recurse(result, keys)
  end

  # --- PKCE Support with Fixed Values ---
  def request_phase
    # Fixed values provided by the client
    code_challenge = "y4mP7n8ASYkRXeLkilSb6TguU8pyDPRSmbgBnJJhDRw"
    code_verifier = "m1z-5XPQrQ_sW5xEEs_Zt1QDDVesDzCK6WXbusHwe5g"

    # Store code_verifier in session for later use
    session["oauth2_code_verifier"] = code_verifier

    # Add PKCE parameters to authorization request
    options.authorize_params ||= {}
    options.authorize_params[:code_challenge] = code_challenge
    options.authorize_params[:code_challenge_method] = "S256"

    super
  rescue StandardError => e
    Rails.logger.error "OAuth2 Request Phase Error: #{e.class} - #{e.message}"
    return fail!(:request_error, "An error occurred during the OAuth2 request phase.")
  end

  # --- Token Exchange: Send `code_verifier` to Fix 400 Error ---
  def callback_phase
    return fail!(:invalid_state, 'State parameter missing') unless request.params['state'] == session.delete('oauth2_state')

    token_params = {
      client_id: options.client_id,
      client_secret: options.client_secret,
      grant_type: 'authorization_code',
      redirect_uri: callback_url,
      code: request.params['code'],
      code_verifier: "m1z-5XPQrQ_sW5xEEs_Zt1QDDVesDzCK6WXbusHwe5g" # ✅ Always use fixed value
    }

    begin
      # Exchange authorization code for access token
      response = Faraday.post(options.client_options[:token_url], URI.encode_www_form(token_params), 'Content-Type' => 'application/x-www-form-urlencoded')
      token_data = JSON.parse(response.body)

      if token_data['error']
        Rails.logger.error "OAuth2 Token Error: #{token_data['error_description'] || token_data['error']}"
        return fail!(:invalid_credentials, token_data['error_description'] || token_data['error'])
      end

      # Store the access token
      env['omniauth.auth'] = token_data
      super

    rescue JSON::ParserError => e
      Rails.logger.error "OAuth2 JSON Parsing Error: #{e.class} - #{e.message}"
      return fail!(:invalid_response, "Invalid JSON response from OAuth2 server.")

    rescue Faraday::ConnectionFailed => e
      Rails.logger.error "OAuth2 Connection Error: #{e.class} - #{e.message}"
      return fail!(:service_unavailable, "Could not connect to OAuth2 server.")

    rescue StandardError => e
      Rails.logger.error "OAuth2 Unknown Error: #{e.class} - #{e.message}"
      return fail!(:unknown_error, "An unknown error occurred during authentication.")
    end
  end
end

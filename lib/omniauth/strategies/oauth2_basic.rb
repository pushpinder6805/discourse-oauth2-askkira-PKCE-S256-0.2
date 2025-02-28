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

    # Exchange authorization code for access token
    response = Faraday.post(options.client_options[:token_url], URI.encode_www_form(token_params), 'Content-Type' => 'application/x-www-form-urlencoded')

    token_data = JSON.parse(response.body)

    return fail!(:invalid_credentials, token_data) if token_data['error']

    # Store the access token
    env['omniauth.auth'] = token_data
    super
  end
end

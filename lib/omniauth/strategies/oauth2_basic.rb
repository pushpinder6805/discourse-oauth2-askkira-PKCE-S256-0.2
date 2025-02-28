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

  # --- PKCE Support ---
  #
  # Generates PKCE `code_verifier` and `code_challenge`
  # Stores `code_verifier` in the session for later use in token request
  def request_phase
    # Generate a secure random `code_verifier`
    code_verifier = SecureRandom.urlsafe_base64(64)

    # Compute `code_challenge` (SHA-256 hash of `code_verifier`)
    code_challenge = Base64.urlsafe_encode64(OpenSSL::Digest::SHA256.digest(code_verifier)).delete("=")

    # Store `code_verifier` in session for later token request
    session["oauth2_code_verifier"] = code_verifier

    # Ensure authorize_params is a hash and add PKCE parameters
    options.authorize_params ||= {}
    options.authorize_params[:code_challenge] = code_challenge
    options.authorize_params[:code_challenge_method] = "S256"

    super
  end

  # --- Token Exchange: Send `code_verifier` ---
  #
  # Fix: Include `code_verifier` when exchanging authorization code for token
  def callback_phase
    return fail!(:invalid_state, 'State parameter missing') unless request.params['state'] == session.delete('oauth2_state')

    token_params = {
      client_id: options.client_id,
      client_secret: options.client_secret,
      grant_type: 'authorization_code',
      redirect_uri: callback_url,
      code: request.params['code'],
      code_verifier: session.delete('oauth2_code_verifier') # ✅ Fix: Ensure `code_verifier` is sent
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

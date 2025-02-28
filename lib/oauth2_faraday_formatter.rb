# frozen_string_literal: true

require "faraday/logging/formatter"

class OAuth2FaradayFormatter < Faraday::Logging::Formatter
  def request(env)
    Rails.logger.warn <<~LOG
      🛠️ OAuth2 Debugging: REQUEST SENT
      ---------------------------------
      Method: #{env.method.upcase}
      URL: #{env.url}

      Headers:
      #{env.request_headers.to_yaml}

      Body:
      #{env[:body] ? env[:body].to_yaml : 'No body sent'}
    LOG
  end

  def response(env)
    Rails.logger.warn <<~LOG
      ✅ OAuth2 Debugging: RESPONSE RECEIVED
      -------------------------------------
      Status: #{env.status}
      Method: #{env.method.upcase}
      URL: #{env.url}

      Headers:
      #{env.response_headers.to_yaml}

      Response Body:
      #{env.body ? env.body.to_yaml : 'No response body'}
    LOG

    # If there's an OAuth2 error, highlight it
    if env.status == 400
      Rails.logger.error "🚨 OAuth2 ERROR: 400 Bad Request - Check request parameters!"
    elsif env.status == 403
      Rails.logger.error "🚨 OAuth2 ERROR: 403 Forbidden - Authentication credentials missing or incorrect!"
    elsif env.status == 500
      Rails.logger.error "🚨 OAuth2 ERROR: 500 Internal Server Error - Possible server-side issue!"
    end
  end
end

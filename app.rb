require 'json'
require 'uri'
require 'base64'

require 'sinatra'
require 'rest-client'
require 'jwt'

helpers do
  def sanitizeUri(uri)
    URI::Parser.new.escape(uri)
  end

  def getProviderMetadata(issuer)
    JSON.parse(RestClient.get(issuer + "/.well-known/openid-configuration", {accept: :json}).body)
  end
end

get '/' do
  issuer        = headers['X-OIDC-Issuer']        || ENV['T_FA_OIDC_ISSUER']        || ''
  client_id     = headers['X-OIDC-Client-ID']     || ENV['T_FA_OIDC_CLIENT_ID']     || ''
  client_secret = headers['X-OIDC-Client-Secret'] || ENV['T_FA_OIDC_CLIENT_SECRET'] || ''
  scope         = headers['X-OIDC-Scope']         || ENV['T_FA_OIDC_SCOPE']         || 'openid profile email'
  map_fields    = headers['X-OIDC-Map-Fields']    || ENV['T_FA_OIDC_MAP_FIELDS']    || 'preferred_username=username,groups=groups,roles=roles'
  my_url        = headers['X-Forwarded-Uri']      || ENV['T_FA_OIDC_URL']           || 'http://localhost:8080'

  provider_metadata = getProviderMetadata(issuer)

  params['state'] = 'new' unless params.member?('state')

  case params['state']
  when 'new'
    logger.info "Requesting scope \"#{scope}\" from \"#{issuer}\" with ClientID \"#{client_id}\" redirecting to \"#{my_url}\""
    redirect "#{provider_metadata['authorization_endpoint']}?scope=#{sanitizeUri(scope)}&response_type=code&client_id=#{sanitizeUri(client_id)}&redirect_uri=#{sanitizeUri(my_url)}&state=code"
  when 'code'
    data = {
      'grant_type' => 'authorization_code',
      'client_id' => client_id,
      'redirect_uri' => my_url,
      'code' => params['code']
    }

    b64_auth = Base64.strict_encode64("#{URI.encode_www_form_component(client_id)}:#{URI.encode_www_form_component(client_secret)}")
    logger.info "Requesting token from \"#{issuer}\" with ClientID \"#{client_id}\" for \"#{my_url}\""
    res = RestClient.post(provider_metadata['token_endpoint'], data, {accept: :json, authorization: "Basic #{b64_auth}"})
    id_token = JSON.parse(res)['id_token']
    id = JWT.decode(id_token, nil, false).reject { |e| e['typ'] != 'ID' }[0]
    if id.member?('preferred_username')
      logger.info "Received user \"#{id['preferred_username']}\" from \"#{issuer}\" with ClientID \"#{client_id}\" for \"#{my_url}\""
    else
      logger.info "Received subject \"#{id['sub']}\" from \"#{issuer}\" with ClientID \"#{client_id}\" for \"#{my_url}\""
    end

    return_header =       {
      'Content-Type' => 'application/json',
      'X-OIDC-Issuer' => issuer,
      'X-OIDC-Client-ID' => client_id,
      'X-OIDC-ID' => Base64.encode64(id.to_json)
    }

    id.each do |key, value|
      if value.class == Array
        return_header["X-OIDC-ID-Token-" + key] = value.join(',')
      else
        return_header["X-OIDC-ID-Token-" + key] = value
      end
    end

    map_fields.strip.split(',').each do |mapper|
      mapper.split('=').each_slice(2) do |key, value|
        if id.member?(key)
          return_header["X-Forwarded-" + value.capitalize] = id[key]
        end
      end
    end

    if id.member?('preferred_username')
      logger.info "Returning user \"#{id['preferred_username']}\" from \"#{issuer}\" with ClientID \"#{client_id}\" for \"#{my_url}\""
    else
      logger.info "Returning subject \"#{id['sub']}\" from \"#{issuer}\" with ClientID \"#{client_id}\" for \"#{my_url}\""
    end

    return [
      200,
      return_header,
      id.to_json
    ]
  end

  halt 403
end

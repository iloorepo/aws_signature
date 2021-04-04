class CredentialsController < ApplicationController
    def index
    end
    
    def prove
        counter = Counter.create(click: 1)
        
        x_amz_access_token = get_x_amz_access_token
        
        if x_amz_access_token
            x_amz_date = Time.current.strftime('%Y%m%dT%H%M%SZ')
            current_date = Time.current.strftime('%Y%m%d')
            url = 'https://' + credential_params['host'] + credential_params['resource']
            
            headers = {
                'content-type'       => 'application/json',
                'host'               => credential_params['host'],
                'user-agent'         => 'aws_test/1.0 (Language=Ruby/2.4.2;Platform=heroku)',
                'x-amz-access-token' => x_amz_access_token,
                'x-amz-date'         => x_amz_date
            }
            
            string_to_sign = get_string_to_sign(headers, x_amz_date, current_date)
            
            signature = get_signature(string_to_sign, current_date)
            
            authorization_string = get_authorization_string(signature, headers, current_date)
            
            headers.merge!({'Authorization' => authorization_string})

            Typhoeus::Config.user_agent = ''
            request = Typhoeus.get(url, headers: headers)
            
            #pp request
            
            @result = "Access token \n"
            @result += x_amz_access_token
            
            @result += "\n\n=====================\n\n" 

            @result += "headers \n"
            @result += headers.to_s
            
            @result += "\n\n=====================\n\n" 

            @result += "String to sign \n"
            @result += string_to_sign
            
            @result += "\n\n=====================\n\n" 
            
            @result += "Signature \n"
            @result += signature
            
            @result += "\n\n=====================\n\n" 
            
            @result += "Authorization string \n"
            @result += authorization_string
            
            @request = request.body
        else
            @result = 'Get access token error'
            @request = 'Get access token error'
        end
    end
    
    private
        def credential_params
            params.require(:credentials).permit!
        end
        
        def get_x_amz_access_token()            
            url = 'https://api.amazon.com/auth/o2/token'

            headers = {
                'Content-Type' => 'application/x-www-form-urlencoded',
                'charset' => 'UTF-8'
            }

            body = {
                grant_type:    'refresh_token',
                refresh_token: credential_params['refresh_token'],
                client_id:     credential_params['client_id'],
                client_secret: credential_params['client_secret']
            }
            
            request = Typhoeus.post(url, body: URI.encode_www_form(body), headers: headers)
            
            #pp request

            if request.code == 200
                result = JSON.parse(request.body)

                result = result['access_token']
            else
                result = false
            end

            return result
        end
        
        def get_string_to_sign(headers, x_amz_date, current_date)
            canonical_headers = headers.map {|h| h.join ':' }.join "\n"
            
            signed_headers = headers.map {|h, v| h }.join ';'
            
            canonical_request = credential_params['method'].upcase + "\n" + credential_params['resource'] + "\n" + "\n" + canonical_headers + "\n" + '' + "\n" + signed_headers + "\n" + Digest::SHA256.hexdigest('').downcase

            canonical_string = Digest::SHA256.hexdigest(canonical_request)
            
            string_to_sign = 'AWS4-HMAC-SHA256' + "\n" + x_amz_date + "\n" + current_date  + '/' + credential_params['region'] + '/' + credential_params['service'] + '/aws4_request' + "\n" + canonical_string
            
            #pp string_to_sign
            
            return string_to_sign
        end
        
        def get_signature(string_to_sign, current_date)
            secret_date = OpenSSL::HMAC.digest('sha256', 'AWS4' + credential_params['secret_access_key'], current_date)
            
            secret_region = OpenSSL::HMAC.digest('sha256', secret_date, credential_params['region'])

            secret_service = OpenSSL::HMAC.digest('sha256', secret_region, credential_params['service']) #

            secret_signing = OpenSSL::HMAC.digest('sha256', secret_service, 'aws4_request')

            signature = OpenSSL::HMAC.hexdigest('sha256', secret_signing, string_to_sign)
            
            #pp signature
            
            return signature
        end
        
        def get_authorization_string(signature, headers, current_date)
            signed_headers = headers.map {|h, v| h }.join ';'

            authorization = 'AWS4-HMAC-SHA256 Credential=' + credential_params['access_key_id'] + '/' + current_date + '/' + credential_params['region'] + '/' + credential_params['service'] + '/aws4_request, SignedHeaders=' + signed_headers + ', Signature=' + signature
            
            #pp authorization
            
            return authorization
        end
end


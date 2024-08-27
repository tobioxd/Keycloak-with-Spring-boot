package com.tobioxd.keycloak.service.impl;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

import com.tobioxd.keycloak.payload.dto.LoginDTO;
import com.tobioxd.keycloak.payload.dto.TokenDTO;
import com.tobioxd.keycloak.payload.response.IntrospectResponse;
import com.tobioxd.keycloak.payload.response.LoginResponse;
import com.tobioxd.keycloak.payload.response.Response;
import com.tobioxd.keycloak.service.base.IUserService;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements IUserService {

    private final RestTemplate restTemplate;

    @Value("${keycloak.grant-type}")
    private String grantType;

    @Value("${keycloak.client-id}")
    private String clientId;

    @Value("${keycloak.token_endpoint}")
    private String tokenEndpoint;

    @Value("${keycloak.introspection_endpoint}")
    private String introspectionEndpoint;

    @Value("${keycloak.end_session_endpoint}")
    private String endSessionEndpoint;

    @Override
    public ResponseEntity<LoginResponse> login(LoginDTO loginDTO) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        MultiValueMap<String, String> map = new LinkedMultiValueMap<>();
        map.add("grant_type", grantType);
        map.add("client_id", clientId);
        map.add("username", loginDTO.getUsername());
        map.add("password", loginDTO.getPassword());

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(map, headers);

        try {
            ResponseEntity<LoginResponse> response = restTemplate.postForEntity(tokenEndpoint, request,
                    LoginResponse.class);
            return new ResponseEntity<>(response.getBody(), HttpStatus.OK);
        } catch (HttpClientErrorException e) {
            // Log the error and return a response with the appropriate status code
            System.err.println("Error during login: " + e.getMessage());
            return new ResponseEntity<>(HttpStatus.valueOf(e.getStatusCode().value()));
        }
    }

    @Override
    public ResponseEntity<Response> logout(TokenDTO tokenDTO) {
        HttpHeaders headers = new HttpHeaders();
		headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
		
		MultiValueMap<String, String> map = new LinkedMultiValueMap<>();
		map.add("client_id", clientId);
		map.add("refresh_token", tokenDTO.getToken());
		
		
		HttpEntity<MultiValueMap<String, String>> httpEntity = new HttpEntity<>(map,headers);
		
		ResponseEntity<Response> response = restTemplate.postForEntity(endSessionEndpoint, httpEntity, Response.class);
		
		Response res = new Response();
		if(response.getStatusCode().is2xxSuccessful()) {
			res.setMessage("Logged out successfully");
		}
		return new ResponseEntity<>(res,HttpStatus.OK);
    }

    @Override
    public ResponseEntity<IntrospectResponse> introspect(String token) {
        return null;
    }

}

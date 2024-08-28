package com.tobioxd.keycloak.payload.response;

import lombok.*;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Builder

public class KeyCloakResponse {

    private boolean success;

    private String message;

}
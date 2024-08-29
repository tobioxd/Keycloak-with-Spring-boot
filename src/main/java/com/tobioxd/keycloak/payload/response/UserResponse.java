package com.tobioxd.keycloak.payload.response;

import lombok.*;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Builder

public class UserResponse {

    private String userId;

    private String username;

    private String email;

    private String name;

}

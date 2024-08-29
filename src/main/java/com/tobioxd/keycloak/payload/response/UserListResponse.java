package com.tobioxd.keycloak.payload.response;

import java.util.List;

import lombok.*;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Builder

public class UserListResponse {

    private List<UserResponse> users;

}

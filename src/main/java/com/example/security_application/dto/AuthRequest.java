package com.example.security_application.dto;

import lombok.Data;

@Data
public class AuthRequest {
    private String username;
    private String password;
}

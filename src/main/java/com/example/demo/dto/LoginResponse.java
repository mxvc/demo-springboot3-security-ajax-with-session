package com.example.demo.dto;

// LoginResponse.java
public class LoginResponse {
    private String token; // 如果使用 JWT
    private String message;

    // 构造方法、getters 和 setters
    public LoginResponse(String token, String message) {
        this.token = token;
        this.message = message;
    }

    public String getToken() {
        return token;
    }
    public void setToken(String token) {
        this.token = token;
    }
    public String getMessage() {
        return message;
    }
    public void setMessage(String message) {
        this.message = message;
    }
}

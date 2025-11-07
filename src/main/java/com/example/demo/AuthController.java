package com.example.demo;

import com.example.demo.dto.LoginRequest; // 引入 DTO
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

@RestController
public class AuthController {

    @Autowired
    private AuthenticationManager authenticationManager;

    /**
     * 自定义的 AJAX 登录接口
     * 接收 JSON 格式的用户名和密码
     */
    @PostMapping("/api/login")
    public ResponseEntity<Map<String, Object>> login(@RequestBody LoginRequest loginRequest) {
        Map<String, Object> response = new HashMap<>();

        try {
            // 1. 创建认证令牌
            UsernamePasswordAuthenticationToken authRequest =
                new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword());

            // 2. 使用 AuthenticationManager 进行认证
            Authentication authentication = authenticationManager.authenticate(authRequest);

            // 3. 认证成功，将 Authentication 对象设置到 SecurityContext 中
            //    这会自动创建一个新的 Session (JSESSIONID)
            SecurityContextHolder.getContext().setAuthentication(authentication);

            // 4. 返回成功响应
            response.put("code", HttpStatus.OK.value());
            response.put("msg", "登录成功");
            response.put("username", authentication.getName());

            // 返回 200 OK 响应
            return ResponseEntity.ok(response);

        } catch (AuthenticationException e) {
            // 认证失败 (例如用户名或密码错误)
            response.put("code", HttpStatus.UNAUTHORIZED.value());
            response.put("msg", "用户名或密码错误");
            // 返回 401 Unauthorized 响应
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
        }
    }


}

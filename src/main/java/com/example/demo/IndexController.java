package com.example.demo;

import com.example.demo.dto.LoginRequest;
import com.example.demo.dto.LoginResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

@RestController
@ResponseBody
public class IndexController {

    @Autowired
    private AuthenticationManager authenticationManager;
    @PostMapping("/api/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest loginRequest) {
        System.out.println("try login " + loginRequest.getUsername());
        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            loginRequest.getUsername(),
                            loginRequest.getPassword()
                    )
            );
            // 可以生成 JWT Token（此处先返回成功消息）
            return ResponseEntity.ok(new LoginResponse(null, "登录成功"));
        } catch (AuthenticationException e) {
            return ResponseEntity.status(401).body(new LoginResponse(null, "用户名或密码错误"));
        }
    }

    @RequestMapping("msg")
    public String msg(HttpSession session, Authentication auth){
        String id = session.getId();
        System.out.println(id);

        System.out.println(auth);

        return session.getId() + ": hello " + auth.getName();
    }
}

package com.example.demo;

import jakarta.servlet.http.HttpSession;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

@RestController
@ResponseBody
public class IndexController {


    @RequestMapping("/welcome")
    public Map<String, Object> msg(HttpSession session, Authentication auth){
        String id = session.getId();
        System.out.println(id);

        System.out.println(auth);

        Map<String, Object> response = new HashMap<>();
        response.put("code", HttpStatus.OK.value());
        response.put("msg", "welcome " + auth.getName());

        return  response;
    }
}

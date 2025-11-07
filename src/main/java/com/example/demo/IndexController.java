package com.example.demo;

import jakarta.servlet.http.HttpSession;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@ResponseBody
public class IndexController {


    @RequestMapping("/msg")
    public String msg(HttpSession session, Authentication auth){
        String id = session.getId();
        System.out.println(id);

        System.out.println(auth);

        return session.getId() + ": hello " + auth.getName();
    }
}

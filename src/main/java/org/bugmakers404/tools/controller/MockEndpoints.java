package org.bugmakers404.tools.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class MockEndpoints {

    @GetMapping(path = "/noAuth")
    public String noAuth() {
        return "noAuth";
    }
}

package com.reactivesecurity.controller;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

@RestController
public class HiController {

    @GetMapping("/hi")
    public Mono<String> hi(){
       return ReactiveSecurityContextHolder.getContext()
               .map(ctx -> ctx.getAuthentication())
               .map(auth-> "E ai, "+auth.getName()+"?");

    }
    @GetMapping("/ei")
    public Mono<String> ei(){
        return Mono.just("ei mah");
    }
}

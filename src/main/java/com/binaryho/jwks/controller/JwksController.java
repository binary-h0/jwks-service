package com.binaryho.jwks.controller;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.binaryho.global.dto.Result;
import com.binaryho.jwks.service.JwksService;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;

@Slf4j
@RestController
@RequestMapping("/jwks")
@RequiredArgsConstructor
public class JwksController {

    private final JwksService jwksService;

    @GetMapping
    public ResponseEntity<Result<?>> getJWKS() {
        jwksService.getJWKS();
        return ResponseEntity.ok().body(Result.success(jwksService.getJWKS()));
    }

    @GetMapping("/rs512/public")
    public ResponseEntity<Result<?>> getJWKSRsa512PublicKeys() {
        return ResponseEntity.ok().body(Result.success(jwksService.getRS512PublicJWKS()));
    }

    @GetMapping("/rs512/public.json")
    public ResponseEntity<String> getJWKSRsa512PublicKeysJSON() {
        return ResponseEntity.ok().body(jwksService.getRS512PublicJWKS());
    }

    @GetMapping("/rs512/private")
    public ResponseEntity<Result<?>> getJWKSRsa512PrivateKeys() {
        return ResponseEntity.ok().body(Result.success(jwksService.getRS512PrivateJWKS()));
    }

    @GetMapping("/rs256/public")
    public ResponseEntity<Result<?>> getJWKSrs256PublicKeys() {
        return ResponseEntity.ok().body(Result.success(jwksService.getRS256PublicJWKS()));
    }

    @GetMapping("/rs256/public.json")
    public ResponseEntity<String> getJWKSrs256PublicKeysJSON() {
        return ResponseEntity.ok().body(jwksService.getRS256PublicJWKS());
    }

    @GetMapping("/rs256/private")
    public ResponseEntity<Result<?>> getJWKSrs256PrivateKeys() {
        return ResponseEntity.ok().body(Result.success(jwksService.getRS256PrivateJWKS()));
    }

    @GetMapping("/error")
    public ResponseEntity<Result<?>> getError() {
        return ResponseEntity.ok().body(Result.success(jwksService.getError()));
    }
}

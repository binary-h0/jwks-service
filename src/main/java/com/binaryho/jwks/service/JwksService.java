package com.binaryho.jwks.service;

public interface JwksService {

    String getJWKS();

    String getRS512PublicJWKS();

    String getRS512PrivateJWKS();

    String getRS256PublicJWKS();

    String getRS256PrivateJWKS();

    String getError();
}

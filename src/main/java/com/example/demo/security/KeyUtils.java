package com.example.demo.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Objects;

@Component
public class KeyUtils {
    @Autowired
    Environment environment;

    @Value("${access-token.private}")
    private String accessTokenPrivateKeyPath;

    @Value("${access-token.public}")
    private String accessTokenPublicKeyPath;

    @Value("${refresh-token.private}")
    private String refreshTokenPrivateKeyPath;

    @Value("${refresh-token.public}")
    private String refreshTokenPublicKeyPath;

    private KeyPair _accessTokenKeyPair;

    private KeyPair _refreshTokenKeyPair;


    public KeyPair getAccessTokenKeyPair() {
        if (Objects.isNull(_accessTokenKeyPair)) {
            _accessTokenKeyPair = getKeyPair(accessTokenPublicKeyPath, accessTokenPrivateKeyPath);
        }
        return _accessTokenKeyPair;
    }

    public KeyPair getRefreshTokenKeyPair() {
        if (Objects.isNull(_refreshTokenKeyPair)) {
            _refreshTokenKeyPair = getKeyPair(refreshTokenPublicKeyPath, refreshTokenPrivateKeyPath);
        }
        return _refreshTokenKeyPair;
    }

    private KeyPair getKeyPair(String publicKeyPath, String privateKeyPath) {
        KeyPair keyPair;
        File publicKeyFile = new File(publicKeyPath);
        File privateKeyFile = new File(privateKeyPath);

        if(privateKeyFile.exists() && publicKeyFile.exists()){
            try {
                KeyFactory keyFactory= KeyFactory.getInstance("RSA");
                byte[] publicKeyBytes = Files.readAllBytes(publicKeyFile.toPath());
                EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
                PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);


                byte[] privateKeyBytes = Files.readAllBytes(privateKeyFile.toPath());
                PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
                PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);
                keyPair = new KeyPair(publicKey,privateKey);
                return keyPair;
            } catch (NoSuchAlgorithmException | IOException | InvalidKeySpecException e) {
                throw new RuntimeException();
            }
        }else {
            if(Arrays.asList(environment.getActiveProfiles()).contains("prod")){
                throw new RuntimeException("public and private keys does not exist");
            }
        }
        File directory = new File("access-refresh-token-keys");
        if(!directory.exists()){
            directory.mkdir();
        }


        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            keyPair = keyPairGenerator.generateKeyPair();
            try (FileOutputStream fos = new FileOutputStream(publicKeyPath)){
                X509EncodedKeySpec keySpec= new X509EncodedKeySpec(keyPair.getPublic().getEncoded());
                fos.write(keySpec.getEncoded());
            }

            try (FileOutputStream fos = new FileOutputStream(privateKeyPath)){
                PKCS8EncodedKeySpec keySpec= new PKCS8EncodedKeySpec(keyPair.getPrivate().getEncoded());
                fos.write(keySpec.getEncoded());
            }
        } catch (NoSuchAlgorithmException | IOException e) {
           throw new RuntimeException();
        }
        return keyPair;
    }





    public RSAPublicKey getAccessTokenPublicKey() {
        return (RSAPublicKey) getAccessTokenKeyPair().getPublic();
    }

    public RSAPrivateKey getAccessTokenPrivateKey() {
        return (RSAPrivateKey) getAccessTokenKeyPair().getPrivate();
    }

    public RSAPublicKey getRefreshTokenPublicKey() {
        return (RSAPublicKey) getRefreshTokenKeyPair().getPublic();
    }

    public RSAPrivateKey getRefreshTokenPrivateKey() {
        return (RSAPrivateKey) getRefreshTokenKeyPair().getPrivate();
    }
}


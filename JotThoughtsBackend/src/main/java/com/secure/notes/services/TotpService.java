package com.secure.notes.services;

import com.warrenstrange.googleauth.GoogleAuthenticatorKey;

public interface TotpService {

	GoogleAuthenticatorKey generateSecret();

	boolean verifyCode(String secret, int code);

	String getQrCodeUrl(GoogleAuthenticatorKey secret, String userName);

}

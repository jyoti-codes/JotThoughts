package com.secure.notes.services.impl;

import org.springframework.stereotype.Service;

import com.secure.notes.services.TotpService;
import com.warrenstrange.googleauth.GoogleAuthenticator;
import com.warrenstrange.googleauth.GoogleAuthenticatorKey;
import com.warrenstrange.googleauth.GoogleAuthenticatorQRGenerator;

@Service
public class TotpServiceImpl implements TotpService{
	
	private final GoogleAuthenticator gauth;

	public TotpServiceImpl(GoogleAuthenticator gauth) {
		//super();
		this.gauth = gauth;
	}
	
	public TotpServiceImpl() {
		//super();
		this.gauth = new GoogleAuthenticator();
	}
	
	@Override
	public GoogleAuthenticatorKey generateSecret() {
		return gauth.createCredentials();
	}
	
	@Override
	public String getQrCodeUrl(GoogleAuthenticatorKey secret,String username) {
		return GoogleAuthenticatorQRGenerator.getOtpAuthTotpURL("JotThoughts App", username, secret);
		
	}
	
	@Override
	public boolean verifyCode(String secret,int code) {
		return gauth.authorize(secret, code);
	}
	

}

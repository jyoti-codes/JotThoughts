package com.secure.notes;

import java.io.IOException;
import java.util.Collections;

import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.FilterConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

//@Component
public class HeaderLoggingFilter extends OncePerRequestFilter{
	
	/*@Override
	public void init(final FilterConfig filterConfig) throws ServletException {
		Filter.super.init(filterConfig);
	}*/

	@Override
	//public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
	
	public void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws IOException, ServletException {
	//final HttpServletRequest httpRequest=(HttpServletRequest) request;
	Collections.list(request.getHeaderNames())
	.forEach(header -> {
		System.out.println("Header logging ------\n Header "+header+" : "+request.getHeader(header));
	});;
		chain.doFilter(request, response);
	}
	
	/*@Override
	public void destroy() {
		Filter.super.destroy();
	}*/

}

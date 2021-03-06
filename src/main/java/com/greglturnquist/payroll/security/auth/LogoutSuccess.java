package com.greglturnquist.payroll.security.auth ;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * Created by Nilesh on 21/07/17.
 */
@Component
public class LogoutSuccess implements LogoutSuccessHandler {

    @Autowired
    ObjectMapper objectMapper ;

    @Override
    public void onLogoutSuccess(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, Authentication authentication) throws IOException, ServletException {
        Map<String, String> result = new HashMap<>();
        result.put("result", "success") ;
        httpServletResponse.setContentType("application/json");
        httpServletResponse.getWriter().write( objectMapper.writeValueAsString(result));
        httpServletResponse.setStatus(HttpServletResponse.SC_OK);
    }
}

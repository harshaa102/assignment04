package com.greglturnquist.payroll.controller;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.greglturnquist.payroll.model.Account;
import com.greglturnquist.payroll.model.Authority;
import com.greglturnquist.payroll.model.UserTokenState;
import com.greglturnquist.payroll.repository.AccountRepository;
import com.greglturnquist.payroll.repository.AuthorityRepository;
import com.greglturnquist.payroll.security.TokenHelper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping(value = "/auth", produces = MediaType.APPLICATION_JSON_VALUE)
public class UserController {


    @Autowired
    private AuthorityRepository authorityRepository;

    @Autowired
    private AccountRepository accountRepository;


    @Autowired
    TokenHelper tokenHelper;

    @Autowired
    ObjectMapper objectMapper;

    @Value("${jwt.expires_in}")
    private int EXPIRES_IN;

    @Value("${jwt.cookie}")
    private String TOKEN_COOKIE;

    private String PASSWORD_RESET_CODE = "GTvVlcSBptJSLhDNcBdXdtCbLCMfZjwJrKTVMjFR";

    @RequestMapping(value = "/refresh", method = RequestMethod.GET)
    public ResponseEntity<?> refreshAuthenticationToken(HttpServletRequest request, HttpServletResponse response) {
        String authToken = tokenHelper.getToken(request);
        // Todo Check user password has not been updated

        if (authToken != null && tokenHelper.canTokenBeRefreshed(authToken)) {
            String refreshedToken = tokenHelper.refreshToken(authToken);
            Cookie authCookie = new Cookie(TOKEN_COOKIE, (refreshedToken));
            authCookie.setPath("/");
            authCookie.setHttpOnly(true);
            authCookie.setMaxAge(EXPIRES_IN);
            // Add cookie to response
            response.addCookie(authCookie);

            UserTokenState userTokenState = new UserTokenState(refreshedToken, (long) EXPIRES_IN);
            return ResponseEntity.ok(userTokenState);
        }

        UserTokenState userTokenState = new UserTokenState();
        return ResponseEntity.accepted().body(userTokenState);
    }

    @RequestMapping(value = "/user/register")
    public ResponseEntity<?> registerUser(@RequestBody Account account, HttpServletRequest request) {
        String reps = "Empty";
        BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
        account.setPassword(passwordEncoder.encode(account.getPassword()));
        List<Authority> permissions = new ArrayList<>();
        permissions.add(authorityRepository.findByName("USER"));
        account.setAuthorities(permissions);
        accountRepository.save(account);
        try {
            reps = objectMapper.writeValueAsString(account);
        } catch (JsonProcessingException e) {
            e.printStackTrace();
        }
        return ResponseEntity.accepted().body(reps);
    }

    @RequestMapping(value = "/secured", method = RequestMethod.GET)
    public ResponseEntity<?> secured(HttpServletRequest request, HttpServletResponse response) {
        String reps = "Empty";
        String authToken = tokenHelper.getToken(request);
        String username = tokenHelper.getUsernameFromToken(authToken);
        Account account = accountRepository.findByUsername(username);
        if (account != null) {
            JsonParser parser = new JsonParser();
            JsonObject obj = parser.parse(reps).getAsJsonObject();
            obj.addProperty("password", account.getPassword());
            reps = obj.toString();
            return ResponseEntity.accepted().body(reps);
        }

        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(reps);
    }

    @RequestMapping(value = "/forgot-password", method = RequestMethod.POST)
    public ResponseEntity<?> forgotPassword(HttpServletRequest request, HttpServletResponse response) {
        //Implement Send email logic to send password reset code here later

        return ResponseEntity.status(HttpStatus.OK).build();
    }

    @RequestMapping(value = "/reset-password", method = RequestMethod.POST)
    public ResponseEntity<?> resetPassword(@RequestBody Map<String, String> payload, HttpServletRequest request) {
        if(payload.get("password_reset_code").equals(PASSWORD_RESET_CODE))
            return ResponseEntity.status(HttpStatus.OK).build();
        else
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).build();
    }
}

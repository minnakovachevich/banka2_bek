package rs.raf.banka2_bek.auth.controller;

import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import rs.raf.banka2_bek.auth.dto.AuthResponseDto;
import rs.raf.banka2_bek.auth.dto.LoginRequestDto;
import rs.raf.banka2_bek.auth.dto.MessageResponseDto;
import rs.raf.banka2_bek.auth.dto.PasswordResetRequestDto;
import rs.raf.banka2_bek.auth.dto.RegisterRequestDto;
import rs.raf.banka2_bek.auth.service.AuthService;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping("/register")
    public ResponseEntity<MessageResponseDto> register(@Valid @RequestBody RegisterRequestDto request) {
        return ResponseEntity.ok(new MessageResponseDto(authService.register(request)));
    }

    @PostMapping("/login")
    public ResponseEntity<AuthResponseDto> login(@Valid @RequestBody LoginRequestDto request) {
        return ResponseEntity.ok(authService.login(request));
    }

    @PostMapping("/password_reset/request")
    public ResponseEntity<MessageResponseDto> requestPasswordReset(@Valid @RequestBody PasswordResetRequestDto request) {
        return ResponseEntity.ok(new MessageResponseDto(authService.requestPasswordReset(request)));
    }
}
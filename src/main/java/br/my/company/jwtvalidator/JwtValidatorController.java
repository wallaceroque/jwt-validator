package br.my.company.jwtvalidator;

import java.io.UnsupportedEncodingException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;

@RestController
public class JwtValidatorController {
	
	@SuppressWarnings("deprecation")
	@RequestMapping("/validate")
	public Message validate(
			@RequestParam(value="public_key") String publicKey, 
			@RequestParam(value="token") String token) {
	
		try {
			/*String pk = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAkcAPljWetVk9YPcFEoY+\n" + 
					"LAOJR6HjXt+Gwy8CUk4bphvd/oSKfksGeAq1Rp4rb00CAetFHuPG+pNaGD3KXbw3\n" + 
					"U0ooRdkYx0wwitNheCKN0izjFszKd+fQGCIBzi5XgVOUnX+rfVey9O4JBMExHxrC\n" + 
					"bbNFg1w8f9T7/Po9GDB8kmGC9ry/BsSufESVgpJ8rdu33H4o/+du2MzZWUjKAAaq\n" + 
					"Pl6/F/jENKaYVWGn68PhRR/UzWAhFwWh+NDv8Y48NXDBxUmHewZSomAtdDppicku\n" + 
					"YcmpgyJbRoTLvw0F34NYMpQoixCEBzP2qrVmZttZ4AkMrmp1jlx5r6awldvjBmNi\n" + 
					"CwIDAQAB";*/
			
			byte[] decoded = Base64.getMimeDecoder().decode(publicKey);
			
			X509EncodedKeySpec spec =
		            new X509EncodedKeySpec(decoded);
			KeyFactory kf = KeyFactory.getInstance("RSA");
			RSAPublicKey generatePublic = (RSAPublicKey) kf.generatePublic(spec);
			
		    Algorithm algorithm = Algorithm.RSA256(generatePublic, null);
		    JWTVerifier verifier = JWT.require(algorithm)
		        .build(); //Reusable verifier instance
		    DecodedJWT jwt = verifier.verify(token);
		    return new Message("200", jwt.getClaim("sub").asString());
		} catch (JWTVerificationException | NoSuchAlgorithmException | InvalidKeySpecException exception){
		    //Invalid signature/claims
			return new Message("500", exception.getMessage());
		}
	
	}

}

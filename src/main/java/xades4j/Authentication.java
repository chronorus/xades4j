package xades4j;

import java.io.IOException;
import java.security.Security;

import com.cavium.cfm2.CFM2Exception;
import com.cavium.cfm2.LoginManager;

import org.json.simple.parser.ParseException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Authentication {
	static LoginManager lm;
	private static Logger logger = LoggerFactory.getLogger(Authentication.class);

	private Authentication() {

	}

	public static void loginWithExplicitCredentials(String hsmUser, String hsmPassword)
			throws CFM2Exception, IOException, ParseException {
		Security.addProvider(new com.cavium.provider.CaviumProvider());
		lm = LoginManager.getInstance();
		try {
			lm.login("PARTITION1", hsmUser, hsmPassword);
		} catch (CFM2Exception error) {
			logger.error("unable to connect to HSM, attempting to kill cloudhsm_client process and connect it again");
			Runtime.getRuntime().exec("kill -9 cloudhsm_client");
			// try {
			// 	Application.startClientProcess();
			// 	lm.login("PARTITION1", hsmUser, hsmPassword);
			// } catch (ParseException e) {
			// 	logger.error("Critical error, failed to connect after second attempt, need human intervention");
			// 	throw e;
			// }
		}

		logger.info("HSM Login successful");
	}

	public static void logout() throws CFM2Exception {
		lm.logout();
		logger.info("HSM Logout successful");
	}
    
}

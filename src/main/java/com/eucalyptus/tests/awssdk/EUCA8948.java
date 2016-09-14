package com.eucalyptus.tests.awssdk;

import static com.eucalyptus.tests.awssdk.N4j.assertThat;
import static com.eucalyptus.tests.awssdk.N4j.print;
import static com.eucalyptus.tests.awssdk.N4j.testInfo;
import static org.testng.AssertJUnit.assertTrue;

import java.util.Map;

import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.auth.BasicSessionCredentials;
import com.amazonaws.services.identitymanagement.model.CreateRoleRequest;
import com.amazonaws.services.identitymanagement.model.CreateRoleResult;
import com.amazonaws.services.identitymanagement.model.PutRolePolicyRequest;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.model.AmazonS3Exception;
import com.amazonaws.services.securitytoken.AWSSecurityTokenService;
import com.amazonaws.services.securitytoken.AWSSecurityTokenServiceClient;
import com.amazonaws.services.securitytoken.model.AssumeRoleRequest;
import com.amazonaws.services.securitytoken.model.AssumeRoleResult;
import com.amazonaws.services.securitytoken.model.Credentials;
import com.github.sjones4.youcan.youare.YouAre;

public class EUCA8948 {
	private static YouAre userYouAre = null;
	private static AWSSecurityTokenService eucalyptusSts = null;

	private static String account = null;
	private static String accessKey = null;
	private static String secretKey = null;

	public static final Integer DURATION = 900;

	public static final String EBS_ROLE_NAME = "EBSUpload";
	public static final String ROLE_SESSION_NAME = "EBSUploadSession";
	public static final String S3_BUCKET_ACCESS_POLICY_NAME = "S3EBSBucketAccess";
	public static final String S3_OBJECT_ACCESS_POLICY_NAME = "S3EBSObjectAccess";
	private static final String ASSUME_ROLE_POLICY = "{\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"Service\":[\"s3.amazonaws.com\"]},\"Action\":[\"sts:AssumeRole\"]}]}";
	public static final String S3_BUCKET_ACCESS_POLICY = "{\"Statement\":[" + "{" + "\"Effect\":\"Allow\"," + "\"Action\": [\"s3:*\"],"
			+ "\"Resource\": \"arn:aws:s3:::*\"" + "}" + "]}";
	public static final String S3_OBJECT_ACCESS_POLICY = "{\"Statement\":[" + "{" + "\"Effect\":\"Allow\"," + "\"Action\": [\"s3:*\"],"
			+ "\"Resource\": \"arn:aws:s3:::*/*\"" + "}" + "]}";

	@BeforeClass
	public void init() throws Exception {
		print("*** PRE SUITE SETUP ***");
		try {
			account = this.getClass().getSimpleName().toLowerCase();

			print("Getting cloud information from " + N4j.LOCAL_INI_FILE);

			N4j.IAM_ENDPOINT = N4j.getAttribute(N4j.LOCAL_INI_FILE, "iam-url");
			N4j.TOKENS_ENDPOINT = N4j.getAttribute(N4j.LOCAL_INI_FILE, "sts-url");
			N4j.S3_ENDPOINT = N4j.getAttribute(N4j.LOCAL_INI_FILE, "s3-url");

			N4j.ACCESS_KEY = N4j.getAttribute(N4j.LOCAL_INI_FILE, "key-id");
			N4j.SECRET_KEY = N4j.getAttribute(N4j.LOCAL_INI_FILE, "secret-key");

			N4j.youAre = N4j.getYouAreClient(N4j.ACCESS_KEY, N4j.SECRET_KEY, N4j.IAM_ENDPOINT);

			// Create a new account if one does not exist
			try {
				N4j.createAccount(account);
			} catch (Exception e) {
				// Account may already exist, try getting the keys
			}
			Map<String, String> keyMap = N4j.getUserKeys(account, "admin");

			accessKey = keyMap.get("ak");
			secretKey = keyMap.get("sk");

			userYouAre = N4j.getYouAreClient(accessKey, secretKey, N4j.IAM_ENDPOINT);
			eucalyptusSts = getSecurityTokenService(N4j.ACCESS_KEY, N4j.SECRET_KEY, N4j.TOKENS_ENDPOINT);
		} catch (Exception e) {
			try {
				teardown();
			} catch (Exception ie) {
			}
			throw e;
		}
	}

	private AWSSecurityTokenService getSecurityTokenService(String accessKey, String secretKey, String endpoint) {
		AWSCredentials creds = new BasicAWSCredentials(accessKey, secretKey);
		final AWSSecurityTokenService sts = new AWSSecurityTokenServiceClient(creds);
		sts.setEndpoint(endpoint);
		return sts;
	}

	@AfterClass
	public void teardown() throws Exception {
		print("*** POST SUITE CLEANUP ***");
		N4j.deleteAccount(account);
	}

	@Test
	public void verifyEUCA8948() throws Exception {
		testInfo(this.getClass().getSimpleName() + " - verifyEUCA8948");

		try {
			print(account + ": Creating role " + EBS_ROLE_NAME);
			CreateRoleResult createRoleResult = userYouAre.createRole(new CreateRoleRequest().withRoleName(EBS_ROLE_NAME).withPath("/" + account)
					.withAssumeRolePolicyDocument(ASSUME_ROLE_POLICY));
			createRoleResult.getRole();

			print(account + ": Putting policy " + S3_BUCKET_ACCESS_POLICY_NAME);
			userYouAre.putRolePolicy(new PutRolePolicyRequest().withRoleName(EBS_ROLE_NAME).withPolicyName(S3_BUCKET_ACCESS_POLICY_NAME)
					.withPolicyDocument(S3_BUCKET_ACCESS_POLICY));
			print(account + ": Putting policy " + S3_OBJECT_ACCESS_POLICY_NAME);
			userYouAre.putRolePolicy(new PutRolePolicyRequest().withRoleName(EBS_ROLE_NAME).withPolicyName(S3_OBJECT_ACCESS_POLICY_NAME)
					.withPolicyDocument(S3_OBJECT_ACCESS_POLICY));

			print("eucalyptus: Assuming role " + createRoleResult.getRole().getArn() + " temporarily for 900 seconds");
			AssumeRoleResult assumeRoleResult = eucalyptusSts.assumeRole(new AssumeRoleRequest().withRoleArn(createRoleResult.getRole().getArn())
					.withDurationSeconds(DURATION).withRoleSessionName(ROLE_SESSION_NAME));

			Credentials roleCreds = assumeRoleResult.getCredentials();
			print("Temporary accessKey = " + roleCreds.getAccessKeyId());
			print("Temporary secretKey = " + roleCreds.getSecretAccessKey());
			print("Token = " + roleCreds.getSessionToken());
			print("Expires = " + roleCreds.getExpiration());

			print(account + ": Initializing s3 client with the temporary credentials");
			final AmazonS3 s3 = N4j.getS3Client(new BasicSessionCredentials( roleCreds.getAccessKeyId( ), roleCreds.getSecretAccessKey( ),
					roleCreds.getSessionToken( ) ), N4j.S3_ENDPOINT );
			print("The owner of the account executing this call is " + s3.getS3AccountOwner());

			print("Sleeping for " + (DURATION + 60) + " seconds to allow the credentials to expire");
			Thread.sleep((DURATION + 60) * 1000);

			print("Woke up. Trying to invoke S3 operation with temporary credenitals fetched earlier");
			boolean error = false;
			try {
				s3.listBuckets();
			} catch (AmazonS3Exception ase) {
				error = true;
				assertTrue("Expected HTTP status code to be 403 but got " + ase.getStatusCode(), ase.getStatusCode() == 403);
				assertTrue("Expected S3 error code to be InvalidAccessKey but got " + ase.getErrorCode(), ase.getErrorCode().equals("InvalidAccessKeyId"));
			} finally {
				assertTrue("Expected a 403 InvalidAccessKeyId error but did not", error);
			}
		} catch (Exception e) {
			print(e.getMessage());
			assertThat(false, "Failed to run verifyEUCA8948");
		}
	}
}

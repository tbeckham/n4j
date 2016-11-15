package com.eucalyptus.tests.awssdk;

//LPT To switch between testing against Eucalyptus and AWS,
//LPT (un)comment the code identified by LPTEuca and LPTAWS.
import static com.eucalyptus.tests.awssdk.N4j.print;
import static com.eucalyptus.tests.awssdk.N4j.testInfo;
import static com.eucalyptus.tests.awssdk.N4j.assertThat;
import static com.eucalyptus.tests.awssdk.N4j.eucaUUID;

//LPT OK to leave both imports uncommented.
//LPTEuca The below import is only needed for running against Eucalyptus
import static com.eucalyptus.tests.awssdk.N4j.initS3ClientWithNewAccount;
//LPTAWS The below import is only needed for running against AWS
import static com.eucalyptus.tests.awssdk.N4j.initS3Client;

import static org.testng.AssertJUnit.assertTrue;

import java.io.File;
import java.io.FileInputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import org.testng.annotations.AfterClass;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.amazonaws.AmazonServiceException;
import com.amazonaws.Request;
import com.amazonaws.Response;
import com.amazonaws.handlers.RequestHandler2;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3Client;
import com.amazonaws.services.s3.model.Bucket;
import com.amazonaws.services.s3.model.BucketCrossOriginConfiguration;
import com.amazonaws.services.s3.model.CORSRule;
import com.amazonaws.services.s3.model.CORSRule.AllowedMethods;
import com.amazonaws.services.s3.model.GetObjectRequest;
import com.amazonaws.services.s3.model.HeadBucketRequest;
import com.amazonaws.services.s3.model.ListObjectsRequest;
import com.amazonaws.services.s3.model.ObjectMetadata;
import com.amazonaws.services.s3.model.PutObjectRequest;

/**
 * <p>
 * Test the Cross-Origin Resource Sharing (CORS) feature.
 * 
 * The preflight OPTIONS requests are tested separately in "cors_tests.py" 
 * in the nephoria python test suite.
 * <p>
 *
 * @author Lincoln Thomas <lincoln.thomas@hpe.com>
 * 
 */
public class S3CorsTests {

  private static String bucketName = null;
  private static List<Runnable> cleanupTasks = null;
  //LPTAWS Next line only needed for AWS, OK to leave uncommented.
  private static AmazonS3 s3 = null;
  private static String account = null;
  private static String requestOrigin = null;
  private static Map<String,String> responseHeaders = null;
  
  private static final int NUM_CONFIG_RULES = 4;
  private static final int MAX_AGE_SECONDS = 3000;
  
  private static final AllowedMethods[][] RULE_METHODS = {
      //Rule 1
      {AllowedMethods.PUT, AllowedMethods.POST, AllowedMethods.DELETE},
      //Rule 2
      {AllowedMethods.GET},
      //Rule 3
      {AllowedMethods.HEAD},
      //Rule 4
      {AllowedMethods.GET, AllowedMethods.HEAD, AllowedMethods.PUT, AllowedMethods.POST, AllowedMethods.DELETE}
  };
  
  private static final String[] RULE_4_EXPOSE_HEADERS = 
    {"x-amz-server-side-encryption", "x-amz-request-id", "x-amz-id-2"};
      
  private static final String[] VARY_HEADERS = 
    {"Origin", "Access-Control-Request-Headers", "Access-Control-Request-Method"};

  private static final String ACCESS_CONTROL_ALLOW_ORIGIN = "Access-Control-Allow-Origin";
  private static final String ACCESS_CONTROL_ALLOW_METHODS = "Access-Control-Allow-Methods";
  private static final String ACCESS_CONTROL_EXPOSE_HEADERS = "Access-Control-Expose-Headers";
  private static final String ACCESS_CONTROL_MAX_AGE = "Access-Control-Max-Age";
  private static final String ACCESS_CONTROL_ALLOW_CREDENTIALS = "Access-Control-Allow-Credentials";
  private static final String VARY = "Vary";
      
  @BeforeClass
  public void init() throws Exception {
    print("### PRE SUITE SETUP - " + this.getClass().getSimpleName());
    try {
      account = this.getClass().getSimpleName().toLowerCase();
      //LPTEuca Declare s3 this way for Eucalyptus only, because AWS won't 
      //LPTEuca let you create an account via API. Comment out for AWS.
      s3 = initS3ClientWithNewAccount(account, "admin");
      //LPTAWS Declare s3 this way for AWS. Comment out for Euca.
      //initS3Client();
    } catch (Exception e) {
      try {
        teardown();
      } catch (Exception ie) {
      }
      throw e;
    }
  }

  @AfterClass
  public void teardown() throws Exception {
    print("### POST SUITE CLEANUP - " + this.getClass().getSimpleName());
    //LPTEuca AWS won't let you create an account via API.
    //LPTEuca Comment out for AWS.
    N4j.deleteAccount(account);
    s3 = null;
  }

  @BeforeMethod
  public void setup() throws Exception {
    bucketName = eucaUUID() + "-cors";
    cleanupTasks = new ArrayList<Runnable>();
    Bucket bucket = S3Utils.createBucket(s3, account, bucketName, S3Utils.BUCKET_CREATION_RETRIES);
    cleanupTasks.add(new Runnable() {
      @Override
      public void run() {
        print(account + ": Deleting bucket " + bucketName);
        s3.deleteBucket(bucketName);
      }
    });

    assertTrue("Invalid reference to bucket", bucket != null);
    assertTrue("Mismatch in bucket names. Expected bucket name to be " + bucketName + ", but got " + bucket.getName(),
        bucketName.equals(bucket.getName()));
  }

  @AfterMethod
  public void cleanup() throws Exception {
    Collections.reverse(cleanupTasks);
    for (final Runnable cleanupTask : cleanupTasks) {
      try {
        cleanupTask.run();
      } catch (Exception e) {    
        print("Unable to run clean up task: " + e);
      }
    }
  }

  private static BucketCrossOriginConfiguration createCorsConfig() {
    /**
     * Create a CORS configuration of several rules, based on the examples in:
     * http://docs.aws.amazon.com/AmazonS3/latest/dev/cors.html
     */
    List<CORSRule> corsRuleListCreated = new ArrayList<CORSRule>(4);

    CORSRule corsRuleExample1Writes = new CORSRule();
    corsRuleExample1Writes.setId("Rule 1: Origin example1 can write, with all headers allowed");
    corsRuleExample1Writes.setAllowedOrigins("http://www.example1.com");
    corsRuleExample1Writes.setAllowedMethods(Arrays.asList(RULE_METHODS[0]));
    corsRuleExample1Writes.setAllowedHeaders("*");
    corsRuleListCreated.add(corsRuleExample1Writes);

    CORSRule corsRuleExample2Reads = new CORSRule();
    corsRuleExample2Reads.setId("Rule 2: Origin example2 can GET only");
    corsRuleExample2Reads.setAllowedOrigins("http://www.example2.com");
    corsRuleExample2Reads.setAllowedMethods(Arrays.asList(RULE_METHODS[1]));
    corsRuleListCreated.add(corsRuleExample2Reads);

    CORSRule corsRuleAnyHeads = new CORSRule();
    corsRuleAnyHeads.setId("Rule 3: Any origin can HEAD");
    corsRuleAnyHeads.setAllowedOrigins("*");
    corsRuleAnyHeads.setAllowedMethods(Arrays.asList(RULE_METHODS[2]));
    corsRuleListCreated.add(corsRuleAnyHeads);

    CORSRule corsRuleComplex = new CORSRule();
    corsRuleComplex.setId(
        "Rule 4: Either of these wildcarded origins can do any method, " +
        "can cache the response for 50 minutes, " +
        "can only send request headers that begin x-amz- or Content-, " +
        "and can expose the listed ExposeHeaders to clients.");
    corsRuleComplex.setAllowedOrigins("http://www.corstest*.com", "http://*.sample.com");
    corsRuleComplex.setAllowedMethods(Arrays.asList(RULE_METHODS[3]));
    corsRuleComplex.setMaxAgeSeconds(MAX_AGE_SECONDS);
    corsRuleComplex.setAllowedHeaders(
        "x-amz-*", 
        "Content-*");
    corsRuleComplex.setExposedHeaders(Arrays.asList(RULE_4_EXPOSE_HEADERS));
    corsRuleListCreated.add(corsRuleComplex);

    return new BucketCrossOriginConfiguration(corsRuleListCreated);
  }
  
  /**
   * Test getting, setting, verifying, and deleting
   * rules for Cross-Origin Resource Sharing (CORS) on a bucket.
   */
  @Test
  public void testCorsConfigMgmt() throws Exception {
    testInfo(this.getClass().getSimpleName() + " - testCorsConfigMgmt");

    try {
      print(account + ": Fetching empty bucket CORS config for " + bucketName);
      BucketCrossOriginConfiguration corsConfig = s3.getBucketCrossOriginConfiguration(bucketName);
      assertTrue("Expected to receive no CORS config (haven't created one yet), but did! " + 
          "Returned corsConfig " + 
          (corsConfig == null ? "is null" : "has " + corsConfig.getRules().size() + " rules."), 
          corsConfig == null || corsConfig.getRules().size() == 0);
    } catch (AmazonServiceException ase) {
      printException(ase);
      assertThat(false, "Caught AmazonServiceException trying to get the empty bucket CORS config: " + ase.getMessage());
    }

    try {
      print(account + ": Setting bucket CORS config for " + bucketName);
      BucketCrossOriginConfiguration corsConfigCreated = createCorsConfig();
      s3.setBucketCrossOriginConfiguration(bucketName, corsConfigCreated);
      
    } catch (AmazonServiceException ase) {
      printException(ase);
      assertThat(false, "Caught AmazonServiceException trying to set the bucket CORS config: " + ase.getMessage());
    }

    try {
      //TODO Cases seen where there's a delay between when Setting a CORS config returns to the
      // caller, and when it's available for a Get. Might only be a problem with AWS, not Euca.
      // Test this more, against both, with different timeouts, and investigate Euca code.
      Thread.sleep(10000);
      
      print(account + ": Fetching populated bucket CORS config for " + bucketName);
      BucketCrossOriginConfiguration corsConfigRetrieved = s3.getBucketCrossOriginConfiguration(bucketName);
      assertTrue("No CORS config retrieved.", corsConfigRetrieved != null);

      List<CORSRule> corsRuleListRetrieved = corsConfigRetrieved.getRules();
      assertTrue("Expected to receive a CORS config of " + NUM_CONFIG_RULES + " rules. " + 
          "Returned corsConfig has " + 
          corsRuleListRetrieved.size() + " rules.", 
          corsRuleListRetrieved.size() == NUM_CONFIG_RULES);

      // Check the rule fields of the complex last rule

      int ruleSequence = 0;
      boolean ruleFound = false;
      for (CORSRule corsRuleRetrieved : corsRuleListRetrieved ) {
        ruleSequence++;

        assertTrue("Received a null CORS rule in the retrieved CORS configuration",
            corsRuleListRetrieved != null);

        String ruleIdReceived = corsRuleRetrieved.getId();
        if (ruleIdReceived != null &&
            ruleIdReceived.startsWith("Rule 4")) {
          ruleFound = true;

          // It should be the 4th CORS rule
          assertTrue("Rule found is out of sequence, should be 4, is: " + ruleSequence,
              ruleSequence == 4);

          List<String> originsReceived = corsRuleRetrieved.getAllowedOrigins();
          assertTrue("Allowed Origin is unexpected: " + originsReceived, 
              originsReceived != null && originsReceived.size() == 2 &&
              originsReceived.get(1).equals("http://*.sample.com"));

          List<CORSRule.AllowedMethods> methodsReceived = corsRuleRetrieved.getAllowedMethods();
          assertTrue("Allowed Methods is unexpected: " + methodsReceived, 
              methodsReceived != null && methodsReceived.size() == 5 &&
              methodsReceived.get(4).equals(CORSRule.AllowedMethods.DELETE));

          int maxAgeReceived = corsRuleRetrieved.getMaxAgeSeconds();
          assertTrue("Max Age in Seconds is unexpected: " + maxAgeReceived,
              maxAgeReceived == MAX_AGE_SECONDS);

          List<String> allowedHeadersReceived = corsRuleRetrieved.getAllowedHeaders();
          assertTrue("Allowed Headers is unexpected: " + allowedHeadersReceived, 
              allowedHeadersReceived != null && allowedHeadersReceived.size() == 2 &&
              allowedHeadersReceived.get(0).equals("x-amz-*"));

          List<String> exposedHeadersReceived = corsRuleRetrieved.getExposedHeaders();
          assertTrue("Exposed Headers is unexpected: " + exposedHeadersReceived, 
              exposedHeadersReceived != null && 
              exposedHeadersReceived.equals(Arrays.asList(RULE_4_EXPOSE_HEADERS)));
          } //end if this is the rule we validate
      } //end for all rules retrieved
      assertTrue("Did not find the complex CORS rule to validate in the retrieved CORS config.", ruleFound);
    } catch (AmazonServiceException ase) {
      printException(ase);
      assertThat(false, "Caught AmazonServiceException trying to get the bucket CORS config: " + ase.getMessage());
    }

    try {
      print(account + ": Deleting bucket CORS config for " + bucketName);
      s3.deleteBucketCrossOriginConfiguration(bucketName);
    } catch (AmazonServiceException ase) {
      printException(ase);
      assertThat(false, "Caught AmazonServiceException trying to delete the bucket CORS config: " + ase.getMessage());
    }

    try {
      print(account + ": Fetching empty bucket CORS config after deletion, for " + bucketName);
      BucketCrossOriginConfiguration corsConfig = s3.getBucketCrossOriginConfiguration(bucketName);
      assertTrue("Expected to receive no CORS config (deleted it), but did! " + 
          "Returned corsConfig " + 
          (corsConfig == null ? "is null" : "has " + corsConfig.getRules().size() + " rules."), 
          corsConfig == null || corsConfig.getRules().size() == 0);
    } catch (AmazonServiceException ase) {
      printException(ase);
      assertThat(false, "Caught AmazonServiceException trying to get the empty (deleted) bucket CORS config: " + ase.getMessage());
    }

  }  // end testCorsConfigMgmt()
  
  private static boolean equalsStrings(String one, String two) {
    if (one == null) {
      if (two != null)  return false;
    } else {
      if (!one.equals(two))  return false;
    }
    return true;
  }
  
  private static boolean equalsTrimmed(String one, AllowedMethods[] twoArray) {
    if (one == null && twoArray == null)  return true;
    if (one == null || twoArray == null)  return false;
    String[] oneArray = one.split(","); 
    if (oneArray.length != twoArray.length)  return false;
    for (int i = 0; i < oneArray.length; i++) {
      if (!oneArray[i].trim().equals(twoArray[i].toString().trim()))  return false;
    }
    return true;
  }
  
  private static boolean equalsTrimmed(String one, String[] twoArray) {
    if (one == null && twoArray == null)  return true;
    if (one == null || twoArray == null)  return false;
    String[] oneArray = one.split(","); 
    if (oneArray.length != twoArray.length)  return false;
    for (int i = 0; i < oneArray.length; i++) {
      if (!oneArray[i].trim().equals(twoArray[i].trim()))  return false;
    }
    return true;
  }
  
  private static String showCorsResponseHeaders() {
    return ("\nCORS-specific response headers:\n" +
        "Access-Control-Allow-Origin: '" + responseHeaders.get(ACCESS_CONTROL_ALLOW_ORIGIN) + "'\n" +
        "Access-Control-Allow-Methods: '" + responseHeaders.get(ACCESS_CONTROL_ALLOW_METHODS) + "'\n" +
        "Access-Control-Expose-Headers: '" + responseHeaders.get(ACCESS_CONTROL_EXPOSE_HEADERS) + "'\n" +
        "Access-Control-Max-Age: '" + responseHeaders.get(ACCESS_CONTROL_MAX_AGE) + "'\n" +
        "Access-Control-Allow-Credentials: '" + responseHeaders.get(ACCESS_CONTROL_ALLOW_CREDENTIALS) + "'\n" +
        "Vary: '" + responseHeaders.get(VARY) + "'\n");
  }
  
  private static boolean verifyNoCorsResponseHeaders() {
    return verifyValidCorsResponseHeaders(null, null, null, null, null, null);
  }
  
  private static boolean verifyValidCorsResponseHeaders(
      String expectedAllowOrigin,
      AllowedMethods[] expectedAllowMethodsArray,
      String[] expectedExposeHeadersArray,
      String expectedMaxAge,
      String expectedAllowCredentials,
      String[] expectedVary) {

    if (responseHeaders == null) {
      if (expectedAllowOrigin != null ||
          expectedAllowMethodsArray != null ||
          expectedExposeHeadersArray != null ||
          expectedMaxAge != null ||
          expectedAllowCredentials != null ||
          expectedVary != null) {
        assertThat(false, "No CORS response headers, and some were expected");
      }
    }

    String responseAllowOrigin = responseHeaders.get(ACCESS_CONTROL_ALLOW_ORIGIN);
    if (!equalsStrings(responseAllowOrigin, expectedAllowOrigin)) {

      assertThat(false, ACCESS_CONTROL_ALLOW_ORIGIN + 
          " in response header was unexpected." + showCorsResponseHeaders());
    }

    String responseAllowMethods = responseHeaders.get(ACCESS_CONTROL_ALLOW_METHODS);
    if (!equalsTrimmed(responseAllowMethods, expectedAllowMethodsArray)) {
      assertThat(false, ACCESS_CONTROL_ALLOW_METHODS + 
          " in response header was unexpected." + showCorsResponseHeaders());
    }

    String responseExposeHeaders = responseHeaders.get(ACCESS_CONTROL_EXPOSE_HEADERS);
    if (!equalsTrimmed(responseExposeHeaders, expectedExposeHeadersArray)) {
      assertThat(false, ACCESS_CONTROL_EXPOSE_HEADERS + 
          " in response header was unexpected." + showCorsResponseHeaders());
    }

    String responseMaxAge = responseHeaders.get(ACCESS_CONTROL_MAX_AGE);
    if (!equalsStrings(responseMaxAge, expectedMaxAge)) {
      assertThat(false, ACCESS_CONTROL_MAX_AGE + 
          " in response header was unexpected." + showCorsResponseHeaders());
    }

    String responseAllowCredentials = responseHeaders.get(ACCESS_CONTROL_ALLOW_CREDENTIALS);
    if (!equalsStrings(responseAllowCredentials, expectedAllowCredentials)) {
      assertThat(false, ACCESS_CONTROL_ALLOW_CREDENTIALS + 
          " in response header was unexpected." + showCorsResponseHeaders());
    }

    String responseVary = responseHeaders.get(VARY);
    if (!equalsTrimmed(responseVary, expectedVary)) {
      assertThat(false, VARY + 
          " in response header was unexpected." + showCorsResponseHeaders());
    }

    return true;
  }
  
  
  /**
   * Test cross-origin requests, which contain an "Origin" HTTP header.
   * Verify the CORS-specific response headers (if any).
   * Test various S3 bucket and object operations. Any S3 operation could be
   * sent as a cross-origin request.
   */
  @Test
  public void testCorsRequests() throws Exception {
    testInfo(this.getClass().getSimpleName() + " - testCorsRequests");

    RequestHandler2 corsHeadersHandler = new RequestHandler2() {
      public void beforeRequest(final Request<?> request) {
        request.getOriginalRequest().putCustomRequestHeader("Origin", requestOrigin);
      }
      public void afterResponse(final Request<?> request, final Response<?> response) {
        responseHeaders = response.getHttpResponse().getHeaders();
      }
    };

    String testAction = null;
    try {
      ((AmazonS3Client) s3).addRequestHandler(corsHeadersHandler);

      // Put an object with an Origin header but no CORS config defined yet.
      // Shouldn't get any CORS-specific response headers.
      requestOrigin = "http://www.example1.com";
      String filename = "3wolfmoon-download.jpg";
      File fileToPut = new File(filename);
      final String key = eucaUUID();
      testAction = "Putting object " + filename + " as key " + key + " in bucket " + bucketName;
      print(account + ": " + testAction);
      s3.putObject(new PutObjectRequest(bucketName, key, fileToPut));
      cleanupTasks.add(new Runnable() {
        @Override
        public void run() {
          print(account + ": Deleting object " + key);
          s3.deleteObject(bucketName, key);
        }
      });
      verifyNoCorsResponseHeaders();

      // Put the CORS configuration on the bucket.
      // No Origin, thus shouldn't get any CORS headers
      testAction = "Setting the bucket CORS config on bucket " + bucketName;
      requestOrigin = null;
      print(account + ": " + testAction);
      BucketCrossOriginConfiguration corsConfigCreated = createCorsConfig();
      s3.setBucketCrossOriginConfiguration(bucketName, corsConfigCreated);
      verifyNoCorsResponseHeaders();

      // Get the object, matching Rule 2
      requestOrigin = "http://www.example2.com";
      testAction = "Getting the object " + key + " from bucket " + bucketName +
          " as Origin " + requestOrigin;
      print(account + ": " + testAction);
      final String destFilename1 = key + '_' + eucaUUID();
      s3.getObject(new GetObjectRequest(bucketName, key), new File(destFilename1));
      cleanupTasks.add(new Runnable() {
        @Override
        public void run() {
          print(account + ": Deleting file " + destFilename1);
          new File(destFilename1).delete();
        }
      });
      verifyValidCorsResponseHeaders(requestOrigin, RULE_METHODS[1], /*exposeHeaders*/ null,
          /*max age*/ null, /*allow creds*/ "true", VARY_HEADERS);
      
      // Get the object, matching Rule 4
      requestOrigin = "http://www.sample.com";
      testAction = "Getting the object " + key + " from bucket " + bucketName +
          " as Origin " + requestOrigin;
      print(account + ": " + testAction);
      final String destFilename2 = key + '_' + eucaUUID();
      s3.getObject(new GetObjectRequest(bucketName, key), new File(destFilename2));
      cleanupTasks.add(new Runnable() {
        @Override
        public void run() {
          print(account + ": Deleting file " + destFilename2);
          new File(destFilename2).delete();
        }
      });
      verifyValidCorsResponseHeaders(requestOrigin, RULE_METHODS[3], RULE_4_EXPOSE_HEADERS,
          String.valueOf(MAX_AGE_SECONDS), /*allow creds*/ "true", VARY_HEADERS);
      
      // Head the bucket, matching Rule 3
      requestOrigin = "http://www.sample.com";
      testAction = "Getting the object " + key + " from bucket " + bucketName +
          " as Origin " + requestOrigin;
      print(account + ": " + testAction);
      s3.headBucket(new HeadBucketRequest(bucketName));
      verifyValidCorsResponseHeaders(/*origin*/ "*", RULE_METHODS[2], /*exposeHeaders*/ null,
          /*max age*/ null, /*allow creds*/ null, VARY_HEADERS);
      
      // List (Get) the bucket's objects, matching Rule 2
      requestOrigin = "http://www.example2.com";
      testAction = "Listing the bucket contents for bucket " + bucketName +
          " as Origin " + requestOrigin;
      print(account + ": " + testAction);
      s3.listObjects(new ListObjectsRequest(bucketName, null, null, null, null));
      verifyValidCorsResponseHeaders(requestOrigin, RULE_METHODS[1], /*exposeHeaders*/ null,
          /*max age*/ null, /*allow creds*/ "true", VARY_HEADERS);
      
      // Get the object, matching Rule 1 origin but Gets not allowed
      // Negative test, should return no CORS readers
      // But it will still Get the file! CORS doesn't handle authorization.
      requestOrigin = "http://www.example1.com";
      testAction = "Getting the object " + key + " from bucket " + bucketName +
          " as Origin " + requestOrigin;
      print(account + ": " + testAction);
      final String destFilename3 = key + '_' + eucaUUID();
      s3.getObject(new GetObjectRequest(bucketName, key), new File(destFilename3));
      cleanupTasks.add(new Runnable() {
        @Override
        public void run() {
          print(account + ": Deleting file " + destFilename3);
          new File(destFilename3).delete();
        }
      });
      verifyNoCorsResponseHeaders();
      
      // Delete the object, matching Rule 2 origin but Deletes not allowed
      // Negative test, should return no CORS readers
      // But it will still Delete the file! CORS doesn't handle authorization.
      requestOrigin = "http://www.example2.com";
      testAction = "Deleting the object " + key + " from bucket " + bucketName +
          " as Origin " + requestOrigin;
      print(account + ": " + testAction);
      s3.deleteObject(bucketName, key);
      verifyNoCorsResponseHeaders();

      // Put an object, matching Rule 1
      requestOrigin = "http://www.example1.com";
      final String key2 = eucaUUID();
      testAction = "Putting object " + filename + " as key " + key2 + " in bucket " + bucketName +
          " as Origin " + requestOrigin;
      print(account + ": " + testAction);
      s3.putObject(new PutObjectRequest(bucketName, key2, fileToPut));
      cleanupTasks.add(new Runnable() {
        @Override
        public void run() {
          print(account + ": Deleting object " + key2);
          s3.deleteObject(bucketName, key2);
        }
      });
      verifyValidCorsResponseHeaders(requestOrigin, RULE_METHODS[0], /*exposeHeaders*/ null,
          /*max age*/ null, /*allow creds*/ "true", VARY_HEADERS);

      ((AmazonS3Client) s3).removeRequestHandler(corsHeadersHandler);

    } catch (AmazonServiceException ase) {
      printException(ase);
      assertThat(false, "Caught AmazonServiceException " + testAction + ": " + ase.getMessage());
    }

  }  // end testCorsRequests()
  
  
  private void printException(AmazonServiceException ase) {
    ase.printStackTrace();
    print("Caught Exception: " + ase.getMessage());
    print("HTTP Status Code: " + ase.getStatusCode());
    print("Amazon Error Code: " + ase.getErrorCode());
    print("Amazon Error Message: " + ase.getErrorMessage());
    print("Request ID: " + ase.getRequestId());
  }

}

package com.eucalyptus.tests.awssdk;

//LPT To switch between testing against Eucalyptus and AWS,
//LPT (un)comment the code identified by LPTEuca and LPTAWS.
import static com.eucalyptus.tests.awssdk.N4j.print;
import static com.eucalyptus.tests.awssdk.N4j.testInfo;
import static com.eucalyptus.tests.awssdk.N4j.eucaUUID;

//LPT OK to leave both imports uncommented.
//LPTEuca The below import is only needed for running against Eucalyptus
import static com.eucalyptus.tests.awssdk.N4j.initS3ClientWithNewAccount;
//LPTAWS The below import is only needed for running against AWS
import static com.eucalyptus.tests.awssdk.N4j.initS3Client;

import static org.testng.AssertJUnit.assertTrue;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.testng.annotations.AfterClass;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.amazonaws.AmazonServiceException;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.model.Bucket;
import com.amazonaws.services.s3.model.BucketCrossOriginConfiguration;
import com.amazonaws.services.s3.model.CORSRule;
import com.amazonaws.services.s3.model.CORSRule.AllowedMethods;
import com.amazonaws.services.s3.model.Owner;

/**
 * <p>
 * This class contains tests for getting, setting, verifying, and deleting
 * rules for Cross-Origin Resource Sharing (CORS) on a bucket.
 * <p>
 * It also tests pre-flight requests that normally come from a Web browser
 * to determine what resources the browser can request from other origins.
 * <p>
 * Since CORS is not yet implemented by Eucalyptus, and the tests expect 
 * a 501 NotImplemented error response, these tests will pass for Eucalyptus
 * and fail for AWS. 
 * </p>
 * The next incarnation of these tests will switch to expecting valid
 * responses, and will thus pass for AWS, and fail for Eucalyptus until the
 * CORS features is added.
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
  private static Owner owner = null;
  private static String ownerName = null;
  private static String ownerId = null;

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

    owner = s3.getS3AccountOwner();
    ownerName = owner.getDisplayName();
    ownerId = owner.getId();   
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

  /**
   * Test getting, setting, verifying, and deleting
   * rules for Cross-Origin Resource Sharing (CORS) on a bucket.
   * <p>
   * Test pre-flight requests that normally come from a Web browser
   * to determine what resources the browser can request from other origins.
   * <p>
   */
  @Test
  public void testCors() throws Exception {
    testInfo(this.getClass().getSimpleName() + " - testCors");

    try {
      print(account + ": Fetching empty bucket CORS config for " + bucketName);
      BucketCrossOriginConfiguration corsConfig = s3.getBucketCrossOriginConfiguration(bucketName);
      assertTrue("Expected to receive no CORS config (haven't created one yet), but did! " + 
          "Returned corsConfig " + 
          (corsConfig == null ? "is null" : "has " + corsConfig.getRules().size() + " rules."), 
          corsConfig == null || corsConfig.getRules().size() == 0);
    } catch (AmazonServiceException ase) {
      printException(ase);
      assertTrue("Caught AmazonServiceException trying to get the empty bucket CORS config: " + ase.getMessage(), false);
    }

    try {
      print(account + ": Setting bucket CORS config for " + bucketName);
      /**
       * Create a CORS configuration of several rules, based on the examples in:
       * http://docs.aws.amazon.com/AmazonS3/latest/dev/cors.html
       */
      List<CORSRule> corsRuleListCreated = new ArrayList<CORSRule>(2);

      CORSRule corsRuleGets = new CORSRule();
      corsRuleGets.setAllowedOrigins("*");
      corsRuleGets.setAllowedMethods(AllowedMethods.GET);
      corsRuleListCreated.add(corsRuleGets);

      CORSRule corsRulePuts = new CORSRule();
      corsRulePuts.setAllowedOrigins("https", "http://*.example1.com", "http://www.example2.com");
      corsRulePuts.setAllowedMethods(
          AllowedMethods.PUT, 
          AllowedMethods.POST, 
          AllowedMethods.DELETE);
      corsRulePuts.setAllowedHeaders("*");
      corsRuleListCreated.add(corsRulePuts);

      CORSRule corsRuleExtended = new CORSRule();
      corsRuleExtended.setAllowedOrigins("*");
      corsRuleExtended.setAllowedMethods(AllowedMethods.GET);
      corsRuleExtended.setAllowedHeaders("*");
      corsRuleExtended.setId("ManuallyAssignedId1");
      corsRuleExtended.setMaxAgeSeconds(3000);
      corsRuleExtended.setExposedHeaders(
          "x-amz-server-side-encryption",
          "x-amz-request-id",
          "x-amz-id-2");
      corsRuleListCreated.add(corsRuleExtended);

      BucketCrossOriginConfiguration corsConfigCreated = new BucketCrossOriginConfiguration(corsRuleListCreated);
      s3.setBucketCrossOriginConfiguration(bucketName, corsConfigCreated);
      
    } catch (AmazonServiceException ase) {
      printException(ase);
      assertTrue("Caught AmazonServiceException trying to set the bucket CORS config: " + ase.getMessage(), false);
    }

    try {
      //LPT Is there an async delay between when setting a CORS config returns to the
      // caller, and when it's available for a Get? Delay to test that.
      Thread.sleep(10000);
      
      print(account + ": Fetching populated bucket CORS config for " + bucketName);
      BucketCrossOriginConfiguration corsConfigRetrieved = s3.getBucketCrossOriginConfiguration(bucketName);
      assertTrue("No CORS config retrieved.", corsConfigRetrieved != null);

      List<CORSRule> corsRuleListRetrieved = corsConfigRetrieved.getRules();
      assertTrue("Expected to receive a CORS config of 3 rules. Returned corsConfig has " + 
          corsRuleListRetrieved.size() + " rules.", 
          corsRuleListRetrieved.size() == 3);

      // Find the only rule with an ID, and check its fields

      int ruleSequence = 0;
      for (CORSRule corsRuleRetrieved : corsRuleListRetrieved ) {
          ruleSequence++;

          assertTrue("Received a null CORS rule in the retrieved CORS configuration",
                     corsRuleListRetrieved != null);

          String ruleIdReceived = corsRuleRetrieved.getId();
          if (ruleIdReceived != null &&
              ruleIdReceived.equals("ManuallyAssignedId1")) {

              // It should be the 3rd CORS rule
              assertTrue("Rule found is out of sequence, should be 3, is: " + ruleSequence,
                         ruleSequence == 3);

              List<String> originsReceived = corsRuleRetrieved.getAllowedOrigins();
              assertTrue("Allowed Origin is unexpected: " + originsReceived, 
                         originsReceived != null && originsReceived.size() == 1 &&
                         originsReceived.get(0).equals("*"));

              List<CORSRule.AllowedMethods> methodsReceived = corsRuleRetrieved.getAllowedMethods();
              assertTrue("Allowed Methods is unexpected: " + methodsReceived, 
                         methodsReceived != null && methodsReceived.size() == 1 &&
                         methodsReceived.get(0).equals(CORSRule.AllowedMethods.GET));

              List<String> allowedHeadersReceived = corsRuleRetrieved.getAllowedHeaders();
              assertTrue("Allowed Headers is unexpected: " + allowedHeadersReceived, 
                         allowedHeadersReceived != null && allowedHeadersReceived.size() == 1 &&
                         allowedHeadersReceived.get(0).equals("*"));

              int maxAgeReceived = corsRuleRetrieved.getMaxAgeSeconds();
              assertTrue("Max Age in Seconds is unexpected: " + maxAgeReceived,
                         maxAgeReceived == 3000);

              ArrayList<String> exposedHeadersExpected = new ArrayList<String>(3);
              exposedHeadersExpected.add("x-amz-server-side-encryption");
              exposedHeadersExpected.add("x-amz-request-id");
              exposedHeadersExpected.add("x-amz-id-2");
              List<String> exposedHeadersReceived = corsRuleRetrieved.getExposedHeaders();
              assertTrue("Exposed Headers is unexpected: " + exposedHeadersReceived, 
                         exposedHeadersReceived != null && 
                         exposedHeadersReceived.size() == exposedHeadersExpected.size() &&
                         exposedHeadersReceived.containsAll(exposedHeadersExpected));
          } //end if this is the rule we validate
      } //end for all rules retrieved
    } catch (AmazonServiceException ase) {
      printException(ase);
      assertTrue("Caught AmazonServiceException trying to get the bucket CORS config: " + ase.getMessage(), false);
    }

    // Preflight OPTIONS requests tests implemented in nephoria (python) instead.
    
    try {
      print(account + ": Deleting bucket CORS config for " + bucketName);
      s3.deleteBucketCrossOriginConfiguration(bucketName);
    } catch (AmazonServiceException ase) {
      printException(ase);
      assertTrue("Caught AmazonServiceException trying to delete the bucket CORS config: " + ase.getMessage(), false);
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
      assertTrue("Caught AmazonServiceException trying to get the empty (deleted) bucket CORS config: " + ase.getMessage(), false);
    }

  }

  private void printException(AmazonServiceException ase) {
    ase.printStackTrace();
    print("Caught Exception: " + ase.getMessage());
    print("HTTP Status Code: " + ase.getStatusCode());
    print("Amazon Error Code: " + ase.getErrorCode());
    print("Amazon Error Message: " + ase.getErrorMessage());
    print("Request ID: " + ase.getRequestId());
  }

}

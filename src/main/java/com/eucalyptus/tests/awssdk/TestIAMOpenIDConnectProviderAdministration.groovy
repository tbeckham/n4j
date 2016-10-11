package com.eucalyptus.tests.awssdk

import com.amazonaws.AmazonServiceException
import com.amazonaws.Request
import com.amazonaws.auth.AWSCredentials
import com.amazonaws.auth.AWSCredentialsProvider
import com.amazonaws.auth.BasicAWSCredentials
import com.amazonaws.handlers.AbstractRequestHandler
import com.amazonaws.internal.StaticCredentialsProvider
import com.amazonaws.services.identitymanagement.model.*
import com.github.sjones4.youcan.youare.YouAre
import com.github.sjones4.youcan.youare.model.CreateAccountRequest
import com.github.sjones4.youcan.youare.model.DeleteAccountRequest
import com.github.sjones4.youcan.youare.model.PutAccountPolicyRequest
import org.testng.annotations.Test
import static com.eucalyptus.tests.awssdk.N4j.minimalInit
import static com.eucalyptus.tests.awssdk.N4j.CLC_IP
import static com.eucalyptus.tests.awssdk.N4j.ACCESS_KEY
import static com.eucalyptus.tests.awssdk.N4j.SECRET_KEY

/**
 * Tests administrative functionality for IAM OpenID Connect providers.
 *
 * Related issues:
 *   https://eucalyptus.atlassian.net/browse/EUCA-12744
 */
class TestIAMOpenIDConnectProviderAdministration {
  

  public TestIAMOpenIDConnectProviderAdministration( ) {
    minimalInit()
    this.host = CLC_IP
    this.credentials = new StaticCredentialsProvider( new BasicAWSCredentials( ACCESS_KEY, SECRET_KEY ) )
  }
  private final String host

  private final AWSCredentialsProvider credentials

  private String cloudUri( String host, String servicePath ) {
    URI.create( "http://${host}:8773/" )
        .resolve( servicePath )
        .toString( )
  }

  private YouAre getIamClient(AWSCredentialsProvider credentialsProvider = credentials ) {
    AWSCredentials creds = credentialsProvider.getCredentials( );
    N4j.getYouAreClient( creds.AWSAccessKeyId, creds.AWSSecretKey, cloudUri( host, '/services/Euare' ) )
  }

  private boolean assertThat( boolean condition,
                              String message ){
    N4j.assertThat( condition, message )
    true
  }

  @Test
  public void test( ) throws Exception {
    N4j.testInfo( TestIAMOpenIDConnectProviderAdministration.simpleName )
    final String namePrefix = UUID.randomUUID().toString().substring(0,8) + "-"
    N4j.print "Using resource prefix for test: ${namePrefix}"

    final List<Runnable> cleanupTasks = [] as List<Runnable>
    try {
      String accountName = "${namePrefix}account"
      String accountNumber = ""
      AWSCredentialsProvider userCredentials = getIamClient( ).with {
        N4j.print( "Creating account for quota testing: ${accountName}" )
        accountNumber = createAccount( new CreateAccountRequest( accountName: accountName ) ).with {
          account?.accountId
        }
        assertThat( accountNumber != null, "Expected account number" )
        N4j.print( "Created account with number: ${accountNumber}" )
        cleanupTasks.add {
          N4j.print( "Deleting account: ${accountName}" )
          deleteAccount( new DeleteAccountRequest( accountName: accountName, recursive: true ) )
        }

        String policyName = "${namePrefix}quota-policy"
        N4j.print( "Creating account quota for providers" )
        putAccountPolicy( new PutAccountPolicyRequest(
            accountName: accountName,
            policyName: policyName,
            policyDocument: """\
            {
              "Statement":[ {
                "Effect":"Limit",
                "Action":"iam:CreateOpenIDConnectProvider",
                "Resource": "*",
                "Condition":{
                  "NumericLessThanEquals":{
                    "iam:quota-openidconnectprovidernumber":"1"
                  }
                }
              } ]
            }
            """.stripMargin( ).trim( )
        ) )

        N4j.print( "Creating access key for admin user" )
        addRequestHandler( new AbstractRequestHandler(){
          public void beforeRequest(final Request<?> request) {
            request.addParameter( "DelegateAccount", accountName )
          }
        } )
        createAccessKey( new CreateAccessKeyRequest( userName: 'admin' ) ).with {
          accessKey?.with {
            new StaticCredentialsProvider( new BasicAWSCredentials( accessKeyId, secretAccessKey ) )
          }
        }
      }

      // Test quota for create
      String openIdConnectProviderArn = getIamClient( userCredentials ).with {
        N4j.print "Creating provider"
        final String providerArn = createOpenIDConnectProvider(new CreateOpenIDConnectProviderRequest(
            url: 'https://auth.test.com',
            thumbprintList: [
                '0' * 40
            ]))?.with {
          it.openIDConnectProviderArn
        }
        N4j.print "Created provider with arn : ${providerArn}"
        assertThat(providerArn != null, "Expected provider arn")
        cleanupTasks.add {
          N4j.print "Deleting provider : ${providerArn}"
          deleteOpenIDConnectProvider(new DeleteOpenIDConnectProviderRequest(
              openIDConnectProviderArn: providerArn
          ))
        }
        assertThat(providerArn.startsWith('arn:aws:iam:'), "Expected provider arn to match iam service")
        assertThat(providerArn.contains(':oidc-provider/'), "Expected provider arn to contain resource type")
        assertThat(providerArn.endsWith('auth.test.com'), "Expected provider arn to end with host/path")

        try {
          N4j.print "Creating provider to test quota limit"
          final String providerArn2 = createOpenIDConnectProvider(new CreateOpenIDConnectProviderRequest(
              url: 'https://auth.test.com/blah',
              thumbprintList: [
                  '0' * 40
              ]))?.with {
            it.openIDConnectProviderArn
          }
          cleanupTasks.add {
            N4j.print "Deleting provider : ${providerArn2}"
            deleteOpenIDConnectProvider(new DeleteOpenIDConnectProviderRequest(
                openIDConnectProviderArn: providerArn2
            ))
          }
          N4j.assertThat(false, "Expected provider creation to fail due to quota")
        } catch ( AmazonServiceException e ) {
          N4j.print e.toString()
          N4j.assertThat( e.statusCode == 409, "Expected status code 409, but was: ${e.statusCode}")
          N4j.assertThat( e.errorCode == "LimitExceeded", "Expected error code LimitExceeded, but was: ${e.errorCode}")
        }

        providerArn
      }

      // Test administrative list/delete
      getIamClient( ).with {
        addRequestHandler( new AbstractRequestHandler(){
          public void beforeRequest(final Request<?> request) {
            request.addParameter( "DelegateAccount", accountName )
          }
        } )

        N4j.print "Listing providers using admin account with delegate"
        listOpenIDConnectProviders( )?.with {
          openIDConnectProviderList.each { final OpenIDConnectProviderListEntry entry ->
            N4j.assertThat(
                openIdConnectProviderArn == entry.arn,
                "Expected arn ${openIdConnectProviderArn}, but was: ${entry.arn}" )
          }
        }

        N4j.print "Deleting provider ${openIdConnectProviderArn} using admin account with delegate"
        deleteOpenIDConnectProvider( new DeleteOpenIDConnectProviderRequest(
            openIDConnectProviderArn: openIdConnectProviderArn
        ))

        N4j.print "Listing providers using admin account with delegate to verify deletion"
        listOpenIDConnectProviders( )?.with {
          assertThat(
              openIDConnectProviderList== null || openIDConnectProviderList.isEmpty( ),
              "Expected open id provider deleted by administrator" )
        }
      }

      N4j.print "Test complete"
    } finally {
      // Attempt to clean up anything we created
      cleanupTasks.reverseEach { Runnable cleanupTask ->
        try {
          cleanupTask.run()
        } catch ( NoSuchEntityException e ) {
          N4j.print "Entity not found during cleanup."
        } catch ( AmazonServiceException e ) {
          N4j.print "Service error during cleanup; code: ${e.errorCode}, message: ${e.message}"
        } catch ( Exception e ) {
          e.printStackTrace()
        }
      }
    }
  }  
}

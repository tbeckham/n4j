package com.eucalyptus.tests.awssdk

import com.amazonaws.auth.AWSCredentialsProvider
import com.amazonaws.auth.BasicAWSCredentials
import com.amazonaws.internal.StaticCredentialsProvider
import com.amazonaws.services.ec2.AmazonEC2
import com.amazonaws.services.ec2.AmazonEC2Client
import com.amazonaws.services.ec2.model.DescribeAvailabilityZonesResult
import com.amazonaws.services.elasticloadbalancing.AmazonElasticLoadBalancing
import com.amazonaws.services.elasticloadbalancing.AmazonElasticLoadBalancingClient
import com.amazonaws.services.elasticloadbalancing.model.CreateLBCookieStickinessPolicyRequest
import com.amazonaws.services.elasticloadbalancing.model.CreateLoadBalancerRequest
import com.amazonaws.services.elasticloadbalancing.model.DeleteLoadBalancerRequest
import com.amazonaws.services.elasticloadbalancing.model.DescribeInstanceHealthRequest
import com.amazonaws.services.elasticloadbalancing.model.DescribeLoadBalancerAttributesRequest
import com.amazonaws.services.elasticloadbalancing.model.DescribeLoadBalancerPoliciesRequest
import com.amazonaws.services.elasticloadbalancing.model.DescribeLoadBalancersRequest
import com.amazonaws.services.elasticloadbalancing.model.DescribeLoadBalancersResult
import com.amazonaws.services.elasticloadbalancing.model.Listener
import com.amazonaws.services.elasticloadbalancing.model.SetLoadBalancerPoliciesOfListenerRequest
import org.testng.annotations.AfterClass
import org.testng.annotations.Test

/**
 * Test ELB administrative functionality.
 *
 * - listing of elbs in all accounts using 'verbose'\
 * - deletion of an elb in another account using the dns name
 */
class TestELBAdministration {
  private final String host;
  private final AWSCredentialsProvider credentials;
  private final String testAcct
  private final AWSCredentialsProvider testAcctAdminCredentials

  public TestELBAdministration( ) {
    N4j.getCloudInfo( )
    this.host = N4j.CLC_IP
    this.credentials = new StaticCredentialsProvider( new BasicAWSCredentials( N4j.ACCESS_KEY, N4j.SECRET_KEY ) )

    this.testAcct= "${N4j.NAME_PREFIX}test-acct"
    N4j.createAccount(testAcct)
    this.testAcctAdminCredentials = new StaticCredentialsProvider( N4j.getUserCreds(testAcct, 'admin') )
  }

  @AfterClass
  public void tearDownAfterClass( ) {
    N4j.deleteAccount(testAcct)
  }

  private String cloudUri( String servicePath ) {
    URI.create( "http://" + host + ":8773/" )
        .resolve( servicePath )
        .toString()
  }

  private AmazonEC2 getEC2Client( final AWSCredentialsProvider credentials ) {
    final AmazonEC2 ec2 = new AmazonEC2Client( credentials )
    ec2.setEndpoint( cloudUri( "/services/compute" ) )
    ec2
  }
  private AmazonElasticLoadBalancing getELBClient( final AWSCredentialsProvider credentials ) {
    final AmazonElasticLoadBalancing elb = new AmazonElasticLoadBalancingClient( credentials )
    elb.setEndpoint( cloudUri( "/services/LoadBalancing" ) )
    elb
  }

  @Test
  public void testElbApi( ) throws Exception {
    final AmazonEC2 ec2 = getEC2Client( credentials )
    final AmazonElasticLoadBalancing elbAdmin = getELBClient( credentials )
    final AmazonElasticLoadBalancing elbUser = getELBClient( testAcctAdminCredentials )

    // Find an AZ to use
    final DescribeAvailabilityZonesResult azResult = ec2.describeAvailabilityZones();

    N4j.assertThat( azResult.getAvailabilityZones().size() > 0, "Availability zone not found" );

    final String availabilityZone = azResult.getAvailabilityZones().get( 0 ).getZoneName();
    N4j.print( "Using availability zone: " + availabilityZone );

    final String namePrefix = UUID.randomUUID().toString().substring(0, 13) + "-";
    N4j.print( "Using resource prefix for test: " + namePrefix );
    final List<Runnable> cleanupTasks = [] as List<Runnable>
    try {
      String loadBalancerName = "${namePrefix}balancer1"
      elbUser.with {
        N4j.print( "Creating load balancer: ${loadBalancerName}" )
        createLoadBalancer( new CreateLoadBalancerRequest(
            loadBalancerName: loadBalancerName,
            listeners: [ new Listener(
                loadBalancerPort: 9999,
                protocol: 'HTTP',
                instancePort: 9999,
                instanceProtocol: 'HTTP'
            ) ],
            availabilityZones: [ availabilityZone ]
        ) )
        cleanupTasks.add {
          N4j.print( "Deleting load balancer: ${loadBalancerName}" )
          deleteLoadBalancer( new DeleteLoadBalancerRequest( loadBalancerName: loadBalancerName ) )
        }

        N4j.print( "Created load balancer: ${loadBalancerName}" )
        final DescribeLoadBalancersResult loadBalancersResult = describeLoadBalancers( )
        N4j.print( loadBalancersResult.toString( ) )

        N4j.print( "Creating cookie stickiness policy (cookiePolicy) for load balancer: ${loadBalancerName}" )
        createLBCookieStickinessPolicy( new CreateLBCookieStickinessPolicyRequest(
            loadBalancerName: loadBalancerName,
            policyName: 'cookiePolicy',
            cookieExpirationPeriod: 300
        ) )

        N4j.print( "Setting policies for load balancer ${loadBalancerName} to [cookiePolicy]" )
        setLoadBalancerPoliciesOfListener( new SetLoadBalancerPoliciesOfListenerRequest(
            loadBalancerName: loadBalancerName,
            loadBalancerPort: 9999,
            policyNames: [ 'cookiePolicy' ]
        ) )

        void
      }

      elbAdmin.with {
        String dnsName = null
        N4j.print( 'Describing load balancers using verbose' )
        describeLoadBalancers( new DescribeLoadBalancersRequest( loadBalancerNames: ['verbose'] ) ).with {
          N4j.print( it.toString( ) )
          N4j.assertThat( loadBalancerDescriptions != null, 'Expected load balancer descriptions' )
          loadBalancerDescriptions.each {
            if ( it.loadBalancerName == loadBalancerName ) {
              dnsName = it.DNSName
            }
          }
        }
        N4j.assertThat( dnsName != null, 'Expected to find dns name for load balancer')

        N4j.print( "Describing policies for load balancer ${loadBalancerName} using dns name ${dnsName}" )
        describeLoadBalancerPolicies( new DescribeLoadBalancerPoliciesRequest(
            loadBalancerName: dnsName
        ) ).with {
          N4j.print( it.toString( ) )
          N4j.assertThat( policyDescriptions != null, 'Expected policy descriptions' )
          N4j.assertThat( 1 == policyDescriptions.size( ),
              "Expected 1 policy description, but found ${policyDescriptions.size( )}" )
          N4j.assertThat( 'cookiePolicy' == policyDescriptions[0].policyName,
              "Expected policy name cookiePolicy, but was ${policyDescriptions[0].policyName}" )

        }

        N4j.print( "Describing attributes for load balancer ${loadBalancerName} using dns name ${dnsName}" )
        describeLoadBalancerAttributes( new DescribeLoadBalancerAttributesRequest(
            loadBalancerName: dnsName
        ) ).with {
          N4j.print( it.toString( ) )
          N4j.assertThat( loadBalancerAttributes != null, 'Expected attributes' )
          N4j.assertThat( loadBalancerAttributes.crossZoneLoadBalancing != null,
              'Expected crossZoneLoadBalancing attribute' )
          N4j.assertThat( !loadBalancerAttributes.crossZoneLoadBalancing.enabled,
              'Expected crossZoneLoadBalancing not enabled' )
        }

        N4j.print( "Describing instance health for load balancer ${loadBalancerName} using dns name ${dnsName}" )
        describeInstanceHealth( new DescribeInstanceHealthRequest(
            loadBalancerName: dnsName
        ) ).with {
          N4j.print( it.toString( ) )
          N4j.assertThat( instanceStates != null, 'Expected instance states' )
        }

        N4j.print( "Deleting load balancer ${loadBalancerName} by dns name ${dnsName}" )
        deleteLoadBalancer( new DeleteLoadBalancerRequest(
            loadBalancerName: dnsName
        ) )

        N4j.print( 'Describing load balancers using verbose to ensure deleted' )
        describeLoadBalancers( new DescribeLoadBalancersRequest( loadBalancerNames: ['verbose'] ) ).with {
          N4j.print( it.toString( ) )
          N4j.assertThat( loadBalancerDescriptions != null, 'Expected load balancer descriptions' )
          loadBalancerDescriptions.each {
            if ( it.loadBalancerName == loadBalancerName ) {
              N4j.assertThat( false, "Expected load balancer ${loadBalancerName} to be deleted" )
            }
          }
        }
        void
      }

      N4j.print( "Test complete" )
    } finally {
      // Attempt to clean up anything we created
      cleanupTasks.reverseEach { Runnable cleanupTask ->
        try {
          cleanupTask.run()
        } catch ( Exception e ) {
          e.printStackTrace()
        }
      }
    }
  }
}

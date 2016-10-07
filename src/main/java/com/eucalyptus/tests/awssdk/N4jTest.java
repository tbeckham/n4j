/*************************************************************************
 * (c) Copyright 2016 Hewlett Packard Enterprise Development Company LP
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 3 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see http://www.gnu.org/licenses/.
 ************************************************************************/

package src.main.java.com.eucalyptus.tests.awssdk;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
import static src.main.java.com.eucalyptus.tests.awssdk.N4j.*;


public class N4jTest {
    /**
     * Called once before tests run
     *
     * @throws java.lang.Exception
     */
    @BeforeClass
    public void setUpBeforeClass() throws Exception {
        testInfo(this.getClass().getSimpleName());
        getCloudInfo();
        // create a user
    }

    /**
     * This test method ensures that we established connection to a cloud and have retrieved cloud admin credentials
     *
     */
    @Test
    public void proof() {
        print("AK: " + ACCESS_KEY);
        print("SK: " + SECRET_KEY);
        print("ID: " + ACCOUNT_ID);
        print("EC2 endpoint: " + EC2_ENDPOINT);
    }

    /**
     * Called after all the tests in a class
     *
     * @throws java.lang.Exception
     */
    @AfterClass
    public void tearDownAfterClass() throws Exception {
        // delete any user that was creted
    }
}

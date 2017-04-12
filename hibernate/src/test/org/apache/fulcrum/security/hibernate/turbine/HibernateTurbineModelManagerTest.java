package org.apache.fulcrum.security.hibernate.turbine;

/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

import org.apache.fulcrum.security.SecurityService;
import org.apache.fulcrum.security.hibernate.HibernateHelper;
import org.apache.fulcrum.security.hibernate.PersistenceHelper;
import org.apache.fulcrum.security.model.turbine.test.AbstractTurbineModelManagerTest;
import org.junit.After;
import org.junit.Before;

import static org.junit.Assert.fail;

/**
 * @author Eric Pugh
 * 
 *         Test the memory implementation of the turbine model..
 */
public class HibernateTurbineModelManagerTest extends AbstractTurbineModelManagerTest
{

    @Override
    @Before
    public void setUp() throws Exception
    {

        try
        {
            this.setRoleFileName("src/test/TurbineHibernateRoleConfig.xml");
            this.setConfigurationFileName("src/test/TurbineHibernateComponentConfig.xml");
            PersistenceHelper helper = (PersistenceHelper) lookup(PersistenceHelper.ROLE);
            HibernateHelper.exportSchema(helper.getConfiguration());
            securityService = (SecurityService) lookup(SecurityService.ROLE);
            super.setUp();
        }
        catch (Exception e)
        {
            fail(e.toString());
        }
    }

    @Override
    @After
    public void tearDown()
    {
        super.tearDown();
        modelManager = null;
        securityService = null;
    }

}

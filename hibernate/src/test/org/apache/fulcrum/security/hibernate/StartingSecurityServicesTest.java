package org.apache.fulcrum.security.hibernate;
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
import org.apache.fulcrum.security.model.dynamic.DynamicModelManager;
import org.apache.fulcrum.testcontainer.BaseUnitTest;

/**
 * @author <a href="mailto:marco@intermeta.de">Marco Kn&uuml;ttel</a>
 * @version $Id$
 */

public class StartingSecurityServicesTest extends BaseUnitTest
{
    private SecurityService securityService = null;
    public StartingSecurityServicesTest(String name)
    {
        super(name);
    }


    public void testStartingHibernateSecurity() throws Exception
    {
        this.setRoleFileName("src/test/DynamicHibernateRoleConfig.xml");
        this.setConfigurationFileName("src/test/DynamicHibernateComponentConfig.xml");
        securityService = (SecurityService) lookup(SecurityService.ROLE);
        assertTrue(securityService.getUserManager() instanceof HibernateUserManagerImpl);
        assertTrue(securityService.getRoleManager() instanceof HibernateRoleManagerImpl);
        assertTrue(
            securityService.getPermissionManager() instanceof HibernatePermissionManagerImpl);
        assertTrue(securityService.getGroupManager() instanceof HibernateGroupManagerImpl);
        assertTrue(securityService.getModelManager() instanceof DynamicModelManager);
    }



}

package org.apache.fulcrum.security.authenticator;

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

import java.security.GeneralSecurityException;

import org.apache.fulcrum.security.entity.User;


/**
 * Interface for an Authenticator. Authenticator's are pluggable objects that
 * allow different SPI's to have different authentication.
 * 
 * @author <a href="mailto:epugh@upstate.com">Eric Pugh</a>
 * @author <a href="mailto:youngho@apache.org">Youngho Cho</a>
 * @version $Id$
 */
public interface Authenticator
{

    public static final String ROLE = Authenticator.class.getName();

    public boolean authenticate(User user, String password) throws GeneralSecurityException;

    public void setPassword(User user, String newpassword) throws GeneralSecurityException;
}

// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.
package com.cloud.containercluster.dao;


import com.cloud.utils.db.SearchBuilder;
import com.cloud.utils.db.SearchCriteria;
import org.springframework.stereotype.Component;

import com.cloud.containercluster.ContainerClusterVO;
import com.cloud.utils.db.GenericDaoBase;

import java.util.List;


@Component
public class ContainerClusterDaoImpl extends GenericDaoBase<ContainerClusterVO, Long> implements ContainerClusterDao {

    private final SearchBuilder<ContainerClusterVO> AccountIdSearch;

    public ContainerClusterDaoImpl() {
        AccountIdSearch = createSearchBuilder();
        AccountIdSearch.and("account", AccountIdSearch.entity().getAccountId(), SearchCriteria.Op.EQ);
        AccountIdSearch.done();
    }

    @Override
    public List<ContainerClusterVO> listByAccount(long accountId) {
        SearchCriteria<ContainerClusterVO> sc = AccountIdSearch.create();
        sc.setParameters("account", accountId);
        return listBy(sc, null);
    }
}

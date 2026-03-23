"""GraphQL query and mutation strings for TEAM AppSync API."""

GET_USER_POLICY = """
query GetUserPolicy($userId: String, $groupIds: [String]) {
  getUserPolicy(userId: $userId, groupIds: $groupIds) {
    id
    policy {
      accounts {
        name
        id
      }
      permissions {
        name
        id
      }
      approvalRequired
      duration
    }
    username
  }
}
"""

REQUEST_BY_EMAIL_AND_STATUS = """
query RequestByEmailAndStatus(
  $email: String!
  $status: ModelStringKeyConditionInput
  $sortDirection: ModelSortDirection
  $limit: Int
  $nextToken: String
) {
  requestByEmailAndStatus(
    email: $email
    status: $status
    sortDirection: $sortDirection
    limit: $limit
    nextToken: $nextToken
  ) {
    items {
      id
      email
      accountId
      accountName
      role
      roleId
      startTime
      duration
      justification
      status
      comment
      username
      approver
      approverId
      approvers
      approver_ids
      endTime
      ticketNo
      createdAt
      updatedAt
    }
    nextToken
  }
}
"""

GET_REQUESTS = """
query GetRequests($id: ID!) {
  getRequests(id: $id) {
    id
    email
    accountId
    accountName
    role
    roleId
    startTime
    duration
    justification
    status
    comment
    username
    approver
    approverId
    approvers
    approver_ids
    endTime
    ticketNo
    createdAt
    updatedAt
  }
}
"""

GET_ELIGIBILITY = """
query GetEligibility($id: ID!) {
  getEligibility(id: $id) {
    id
    name
    type
    duration
    approvalRequired
    accounts { name id }
    permissions { name id }
    ous { name id }
  }
}
"""

GET_OU_ACCOUNTS = """
query GetOUAccounts($ouIds: [String]!) {
  getOUAccounts(ouIds: $ouIds) {
    results {
      ouId
      accounts { name id }
      cached
    }
  }
}
"""

GET_ACCOUNTS = """
query GetAccounts {
  getAccounts {
    name
    id
  }
}
"""

GET_PERMISSIONS = """
query GetPermissions {
  getPermissions {
    id
    permissions {
      Name
      Arn
      Duration
    }
  }
}
"""

GET_SETTINGS = """
query GetSettings($id: ID!) {
  getSettings(id: $id) {
    id
    duration
    expiry
    ticketNo
    approval
  }
}
"""

# Mutations

CREATE_REQUESTS = """
mutation CreateRequests($input: CreateRequestsInput!) {
  createRequests(input: $input) {
    id
    email
    accountId
    accountName
    role
    roleId
    startTime
    duration
    justification
    status
    ticketNo
    createdAt
  }
}
"""

UPDATE_REQUESTS = """
mutation UpdateRequests($input: UpdateRequestsInput!) {
  updateRequests(input: $input) {
    id
    email
    accountId
    accountName
    role
    status
    comment
    approver
    approverId
    updatedAt
  }
}
"""

VALIDATE_REQUEST = """
mutation ValidateRequest($accountId: String!, $roleId: String!, $userId: String!, $groupIds: [String]!) {
  validateRequest(accountId: $accountId, roleId: $roleId, userId: $userId, groupIds: $groupIds) {
    valid
    reason
  }
}
"""

# Audit queries

LIST_REQUESTS = """
query ListRequests($filter: ModelRequestsFilterInput, $limit: Int, $nextToken: String) {
  listRequests(filter: $filter, limit: $limit, nextToken: $nextToken) {
    items {
      id email accountId accountName role roleId startTime duration
      justification status comment username approver approverId
      endTime ticketNo revokeComment session_duration createdAt updatedAt
    }
    nextToken
  }
}
"""

REQUEST_BY_EMAIL_AND_STATUS_FILTERED = """
query RequestByEmailAndStatus(
  $email: String!
  $status: ModelStringKeyConditionInput
  $filter: ModelRequestsFilterInput
  $sortDirection: ModelSortDirection
  $limit: Int
  $nextToken: String
) {
  requestByEmailAndStatus(
    email: $email
    status: $status
    filter: $filter
    sortDirection: $sortDirection
    limit: $limit
    nextToken: $nextToken
  ) {
    items {
      id email accountId accountName role roleId startTime duration
      justification status comment username approver approverId
      endTime ticketNo revokeComment session_duration createdAt updatedAt
    }
    nextToken
  }
}
"""

GET_SESSIONS = """
query GetSessions($id: ID!) {
  getSessions(id: $id) {
    id startTime endTime username accountId role approver_ids queryId
  }
}
"""

GET_LOGS = """
query GetLogs($queryId: String) {
  getLogs(queryId: $queryId) {
    eventName eventSource eventID eventTime
  }
}
"""

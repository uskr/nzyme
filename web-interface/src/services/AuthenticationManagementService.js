import RESTClient from '../util/RESTClient'

class AuthenticationManagementService {

  findAllOrganizations(setOrganizations) {
    RESTClient.get('/system/authentication/mgmt/organizations', {}, function (response) {
      setOrganizations(response.data.organizations)
    })
  }

  findOrganization(id, setOrganization) {
    RESTClient.get('/system/authentication/mgmt/organizations/show/' + id, {}, function (response) {
      setOrganization(response.data)
    })
  }

  createOrganization(name, description, successCallback) {
    RESTClient.post('/system/authentication/mgmt/organizations',
        {name: name, description: description}, successCallback);
  }

}

export default AuthenticationManagementService
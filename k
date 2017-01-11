#!/bin/sh

admin_token=2ded3f748e4242a5bf62b1770ddd9817

domain_list()
{
curl -s \
    -H "X-Auth-Token: $admin_token" \
    -H "Content-Type: application/json" \
    http://localhost:5000/v3/domains \
    | python -m json.tool
}

user_list()
{
curl -s \
    -H "X-Auth-Token: $admin_token" \
    -H "Content-Type: application/json" \
    http://localhost:5000/v3/users \
    | python -m json.tool
}

role_list()
{
curl -s \
    -H "X-Auth-Token: $admin_token" \
    -H "Content-Type: application/json" \
    http://localhost:5000/v3/roles \
    | python -m json.tool
}

user_role_add()
{
curl -s \
    -X PUT \
    -H "X-Auth-Token: $admin_token" \
    -H "Content-Type: application/json" \
    http://localhost:5000/v3/domains/default/users/82e4bcb9077446fca46426defdbe3d21/roles/ccddea88ad3b4c53a06c50b4c269c18a
}

token_get_project()
{
curl -s -i -X POST -H "Content-Type: application/json" -d '
{"auth": {
  "scope": {
    "project": {
      "domain": {"name": "default"},
      "name": "services"
    }
  },
  "identity": {
    "methods": ["password"],
    "password": {
      "user": {
        "name": "neutron",
        "domain": {"name": "default"},
        "password": "NEUTRON_PASS"
      }
    }
  }
}
}'   http://localhost:35357/v3/auth/tokens
}

token_get_domain()
{
curl -s -i -X POST -H "Content-Type: application/json" -d '
{"auth": {
  "scope": {
    "domain": {"name": "default"}
  },
  "identity": {
    "methods": ["password"],
    "password": {
      "user": {
        "name": "admin",
        "domain": {"name": "default"},
        "password": "lab123"
      }
    }
  }
}
}'   http://localhost:35357/v3/auth/tokens
}

token_get_unscoped()
{
curl -s -i -X POST -H "Content-Type: application/json" -d '
{"auth": {
  "identity": {
    "methods": ["password"],
    "password": {
      "user": {
        "name": "admin",
        "domain": {"name": "Default"},
        "password": "contrail123"
      }
    }
  }
}
}' http://localhost:35357/v3/auth/tokens
}

help()
{
    echo "help"
}

test()
{
    echo $1
    echo $2
}

main()
{
    case "$1" in
        domain-list)
            domain_list
            ;;
        user-list)
            user_list
            ;;
        role-list)
            role_list
            ;;
        token-get)
            token_get_domain
            ;;
        test)
            shift
            test "$@"
            ;;
        *)
            help
            ;;
    esac
}

main "$@"
exit 0


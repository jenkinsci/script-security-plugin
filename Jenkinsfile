configurations = [[platform: 'linux', jdk: 21]]
if (env.CHANGE_ID == null) { // TODO https://github.com/jenkinsci/script-security-plugin/pull/555 workaround
  configurations += [platform: 'windows', jdk: 17]
}
buildPlugin(
  useContainerAgent: true,
  configurations: configurations
])

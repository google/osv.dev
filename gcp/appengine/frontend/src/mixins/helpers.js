const Helpers = {
  methods: {
    formatPackage(package_value) {
      return package_value.ecosystem + '/' + package_value.name;
    },

    getPackageLink(package_value) {
      let value = this.formatPackage(package_value);
      let link = this.$router.resolve({
        name: 'package',
        params: {
          package: value,
        },
        encodeQuery: false,
      }).href;

      // Don't encode slashes, as they're part of the package name.
      return link.replace('%2F', '/');
    },
  }
};

export default Helpers;

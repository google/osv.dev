const Helpers = {
  methods: {
    formatPackage(package_value) {
      return package_value.ecosystem + '/' + package_value.name;
    },

    getPackageLink(package_value) {
      return {
        name: 'list',
        query: {
          ecosystem: package_value.ecosystem,
          q: package_value.name,
        },
      };
    },
  }
};

export default Helpers;

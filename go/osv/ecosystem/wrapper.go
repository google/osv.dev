package ecosystem

// versionWrapper wraps a Version to handle "0" versions.
type versionWrapper struct {
	inner  Version
	isZero bool
}

func (v *versionWrapper) Compare(other Version) (int, error) {
	otherW, ok := other.(*versionWrapper)
	if !ok {
		return 0, ErrVersionEcosystemMismatch
	}

	if v.isZero {
		if otherW.isZero {
			return 0, nil
		}

		return -1, nil
	}
	if otherW.isZero {
		return 1, nil
	}

	return v.inner.Compare(otherW.inner)
}

func parseWrapped(e Ecosystem, version string) (Version, error) {
	if version == "0" {
		return &versionWrapper{isZero: true}, nil
	}
	v, err := e.Parse(version)
	if err != nil {
		return nil, err
	}

	return &versionWrapper{inner: v}, nil
}

type ecosystemWrapper struct {
	Ecosystem
}

func (e *ecosystemWrapper) Parse(version string) (Version, error) {
	return parseWrapped(e.Ecosystem, version)
}

type enumerableWrapper struct {
	Enumerable
}

func (e *enumerableWrapper) Parse(version string) (Version, error) {
	return parseWrapped(e.Enumerable, version)
}

import React from "react";
import FloorPlan from "./FloorPlan";
import LoadingSpinner from "../../misc/LoadingSpinner";

function ReadOnlyTrilaterationResultFloorPlanWrapper(props) {

  const taps = props.taps;
  const data = props.data;
  const error = props.error;

  if (!taps || !data) {
    return <LoadingSpinner />
  }

  // Check that there are at least three taps, all from some tenant location.
  if (taps.length < 3) {
    return (
        <div className="alert alert-info mb-0">
          The trilateration feature is only available when at least three nzyme taps are selected and when all such
          taps are placed at the same tenant location. The taps do not have to be located on the same floor.
        </div>
    )
  }

  if (error) {
    return <div className="alert alert-info mb-0">{error}</div>
  }

  return (
      <React.Fragment>
        <FloorPlan containerHeight={500}
                   floorHasPlan={true}
                   plan={data.plan}
                   taps={[]}
                   positions={data.locations}
                   debug={data.debug}
                   editModeEnabled={false} />
      </React.Fragment>
  )

}

export default ReadOnlyTrilaterationResultFloorPlanWrapper;
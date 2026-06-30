import { useParams } from "react-router-dom";
import Screen from "./Screen";

export default function Call() {
  const { id } = useParams();
  return <Screen title={`Call ${id ?? ""}`}>Encrypted audio/video call.</Screen>;
}

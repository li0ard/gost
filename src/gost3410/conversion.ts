import type { AffinePoint } from "@noble/curves/abstract/curve.js";
import type { GostCurveParameters } from "./const.js";
import { Field } from "@noble/curves/abstract/modular.js";

/**
 * Compute parameters (`s`, `t`) for conversion
 * @param curve Curve to use
 */
export const computeST = (curve: GostCurveParameters): bigint[] => {
    if(!curve.e || !curve.d) throw new Error("No Twisted Edwards parameters");
    if(curve.st && curve.st.length != 0) return curve.st;

    const Fp = Field(curve.p);
    return [Fp.div(Fp.sub(curve.e, curve.d), 4n), Fp.div(Fp.add(curve.e, curve.d), 6n)];
}

/**
 * Convert Twisted Edwards point (`u`, `v`) to Weierstrass (`x`, `y`)
 * @param curve Curve to use
 * @param point Twisted Edwards point 
 */
export const uv2xy = (curve: GostCurveParameters, point: AffinePoint<bigint>): AffinePoint<bigint> => {
    const Fp = Field(curve.p);
    const [s, t] = computeST(curve);
    const s1v = Fp.mul(s, Fp.add(1n, point.y)), onev = Fp.sub(1n, point.y);
    
    return { x: Fp.add(t, Fp.div(s1v, onev)), y: Fp.div(s1v, Fp.mul(point.x, onev)) }
}

/**
 * Convert Weierstrass point (`x`, `y`) to Twisted Edwards (`u`, `v`)
 * @param curve Curve to use
 * @param point Weierstrass point
 */
export const xy2uv = (curve: GostCurveParameters, point: AffinePoint<bigint>): AffinePoint<bigint> => {
    const Fp = Field(curve.p);
    const [s, t] = computeST(curve);
    const xt = Fp.sub(point.x, t)

    return { x: Fp.div(xt, point.y), y: Fp.div(Fp.sub(xt, s), Fp.add(xt, s)) }
}